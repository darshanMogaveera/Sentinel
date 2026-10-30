import os
import json
import joblib
import uuid
import numpy as np
from datetime import datetime
import xgboost as xgb

from backend.services.logging_service import logger_service
from backend.services.database_service import db_service


class LiveInferenceService:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = []
        
        import threading
        self.correlation_state = {}
        self.correlation_lock = threading.Lock()
        self.MIN_DISTINCT_PORTS = 10
        self.WINDOW_SECONDS = 60
        
        self.models_loaded = False
        self._load_models()

    def _load_models(self):
        try:
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            live_path = os.path.join(project_root, "backend", "models", "live_nfstream")
            
            model_path = os.path.join(live_path, "final_xgboost_model.joblib")
            scaler_path = os.path.join(live_path, "scaler.joblib")
            label_encoder_path = os.path.join(live_path, "label_encoder.joblib")
            features_path = os.path.join(live_path, "feature_names.joblib")

            paths_to_check = [model_path, scaler_path, label_encoder_path, features_path]
            if not all(os.path.exists(p) for p in paths_to_check):
                logger_service.logger.error("Live CIC models not found. Skipping live inference initialization.")
                return

            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.label_encoder = joblib.load(label_encoder_path)
            self.feature_names = joblib.load(features_path)

            if len(self.feature_names) != 69:
                raise ValueError(f"Feature names length is {len(self.feature_names)}, expected 69")

            self.models_loaded = True

            logger_service.logger.info("Live CIC XGBoost model loaded successfully.")
            logger_service.logger.info(f"Model expects 69 features.")

        except Exception as e:
            logger_service.log_error(e, {"context": "LiveInferenceService Model loading"})
            raise

    def predict(
        self,
        features: list,
        flow_meta: dict,
        run_id: str = None,
        skip_correlation: bool = False
    ) -> dict:

        if not self.models_loaded:
            raise ValueError("Live models not loaded.")

        if len(features) != 69:
            raise ValueError(f"Expected 69 features from live extractor, got {len(features)}")

        if np.isnan(features).any() or np.isinf(features).any():
            raise ValueError("NaN or Inf found in features.")

        # Scale features
        scaled_features = self.scaler.transform([features])

        # Predict
        probas = self.model.predict_proba(scaled_features)[0]
        pred_idx = int(np.argmax(probas))
        confidence = float(probas[pred_idx])
        
        pred_label = self.label_encoder.inverse_transform([pred_idx])[0]

        is_threat = False
        threat_type = "none"
        explanation_text = "Normal traffic pattern"

        if pred_label != "BENIGN":
            is_threat = True
            threat_type = pred_label
            explanation_text = f"Sentinel classified this traffic as {pred_label} with {confidence*100:.1f}% confidence."

        protocol_val = flow_meta.get("protocol")
        protocol_raw = {
            "proto_tcp": 1 if protocol_val == 6 else 0,
            "proto_udp": 1 if protocol_val == 17 else 0,
            "proto_icmp": 1 if protocol_val == 1 else 0,
            "proto_other": 1 if protocol_val not in (1, 6, 17) else 0
        } if protocol_val is not None else {}

        top_features = []
        try:
            dmatrix = xgb.DMatrix(scaled_features, feature_names=self.feature_names)
            contribs = self.model.get_booster().predict(dmatrix, pred_contribs=True)[0]
            feature_contribs = contribs[:-1]
            
            shap_list = []
            for i, name in enumerate(self.feature_names):
                shap_list.append({
                    "feature": name,
                    "raw_value": float(features[i]),
                    "impact": float(feature_contribs[i])
                })
            
            shap_list.sort(key=lambda x: abs(x["impact"]), reverse=True)
            top_features = shap_list[:5]
        except Exception as e:
            logger_service.logger.warning(f"Failed to extract SHAP values: {e}")
            if is_threat:
                explanation_text += " Model contribution explanation unavailable for this prediction."

        explanation = {
            "text": explanation_text,
            "top_features": top_features,
            "protocol_raw": protocol_raw,
            "src_port": flow_meta.get("src_port"),
            "dst_port": flow_meta.get("dst_port")
        }

        prediction_result = {
            "threat": is_threat,
            "confidence": float(confidence),
            "threat_type": threat_type,
            "explanation": json.dumps(explanation),
            "rf_prediction": 1 if is_threat else 0, # compatibility
            "if_prediction": 1, # compatibility
            "source_ip": flow_meta.get("src_ip", "unknown"),
            "dest_ip": flow_meta.get("dst_ip", "unknown"),
            "protocol": flow_meta.get("protocol"),
            "fwd_syn_packets": flow_meta.get("fwd_syn_packets", 0),
            "fwd_rst_packets": flow_meta.get("fwd_rst_packets", 0),
            "fwd_fin_packets": flow_meta.get("fwd_fin_packets", 0),
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": str(uuid.uuid4()),
            "run_id": run_id
        }

        prediction_id = db_service.save_prediction(prediction_result)

        alert_created = False
        if is_threat and not skip_correlation:
            alert_created = self._handle_correlation(prediction_id, prediction_result, explanation)

        prediction_result["id"] = prediction_id
        prediction_result["alerted"] = alert_created

        return prediction_result

    def _handle_correlation(self, prediction_id, prediction_result, explanation) -> bool:
        import time
        src_ip = prediction_result.get("source_ip")
        dst_ip = prediction_result.get("dest_ip")
        dst_port = explanation.get("dst_port")
        
        if not src_ip or not dst_ip or dst_port is None:
            return False
            
        protocol = prediction_result.get("protocol")
        fwd_syn = prediction_result.get("fwd_syn_packets", 0)
        fwd_rst = prediction_result.get("fwd_rst_packets", 0)
        fwd_fin = prediction_result.get("fwd_fin_packets", 0)
        
        # Suppress response/backscatter artifacts (e.g. Victim RSTs or CDN FINs)
        # If the forward direction has NO SYNs but contains RSTs or FINs, it is a response/teardown, not a scan probe.
        if protocol == 6 and fwd_syn == 0 and (fwd_rst > 0 or fwd_fin > 0):
            return False
            
        key = (src_ip, dst_ip)
        run_id = prediction_result.get("run_id")
        now = time.time()
        
        alert_created = False
        with self.correlation_lock:
            if len(self.correlation_state) > 1000:
                keys_to_delete = []
                for k, v in self.correlation_state.items():
                    v["observations"] = [obs for obs in v.get("observations", []) if now - obs["timestamp"] <= self.WINDOW_SECONDS]
                    if "run_states" in v:
                        for r_k, r_v in list(v["run_states"].items()):
                            r_v["observations"] = [obs for obs in r_v.get("observations", []) if now - obs["timestamp"] <= self.WINDOW_SECONDS]
                            if not r_v["observations"]:
                                del v["run_states"][r_k]
                    if not v["observations"] and not v.get("run_states"):
                        keys_to_delete.append(k)
                for k in keys_to_delete:
                    del self.correlation_state[k]
                    
            if key not in self.correlation_state:
                self.correlation_state[key] = {
                    "observations": [],
                    "alerted": False,
                    "run_states": {}
                }
            
            state = self.correlation_state[key]
            if "run_states" not in state:
                state["run_states"] = {}
            if "observations" not in state:
                state["observations"] = []
            if "alerted" not in state:
                state["alerted"] = False

            # Scope by run_id if provided (simulation run boundary), otherwise use global host-pair state
            if run_id:
                if run_id not in state["run_states"]:
                    state["run_states"][run_id] = {
                        "observations": [],
                        "alerted": False
                    }
                active_target = state["run_states"][run_id]
            else:
                active_target = state

            # Prune observations older than WINDOW_SECONDS
            active_target["observations"] = [
                obs for obs in active_target.get("observations", [])
                if now - obs["timestamp"] <= self.WINDOW_SECONDS
            ]

            # If all observations in the sliding window have expired, reset alerted flag for this target
            if not active_target["observations"]:
                active_target["alerted"] = False

            active_target["observations"].append({
                "timestamp": now,
                "dst_port": dst_port,
                "prediction_id": prediction_id
            })
            
            unique_ports = len(set(obs["dst_port"] for obs in active_target["observations"]))
            
            if unique_ports >= self.MIN_DISTINCT_PORTS:
                if not active_target["alerted"]:
                    if not prediction_id:
                        logger_service.logger.error(
                            f"[CORRELATION][{run_id}] Cannot save alert for {src_ip} -> {dst_ip}: prediction_id is None (persistence failed)."
                        )
                    else:
                        print(f"!!! TRIGGERING ALERT FOR {src_ip} -> {dst_ip} with {unique_ports} ports (run_id={run_id}) !!!")
                        logger_service.logger.warning(
                            f"[CORRELATION][{run_id}] PortScan confirmed: source={src_ip} target={dst_ip} unique_ports={unique_ports}/{self.MIN_DISTINCT_PORTS} window={self.WINDOW_SECONDS}s"
                        )
                        saved_alert_id = db_service.save_alert(prediction_id, severity="high")
                        if saved_alert_id:
                            active_target["alerted"] = True
                            alert_created = True
                            logger_service.logger.info(
                                f"[CORRELATION][{run_id}] Alert successfully saved with alert_id={saved_alert_id} for prediction_id={prediction_id}"
                            )
                        else:
                            logger_service.logger.error(
                                f"[CORRELATION][{run_id}] Failed to persist alert for {src_ip} -> {dst_ip} (prediction_id={prediction_id}). Will allow retry on later flow."
                            )
                else:
                    logger_service.logger.info(
                        f"[CORRELATION][{run_id}] PortScan threshold satisfied ({unique_ports}/{self.MIN_DISTINCT_PORTS} ports) but duplicate alert suppressed (run already alerted)"
                    )
            else:
                logger_service.logger.info(
                    f"[CORRELATION][{run_id}] ML PortScan candidate: source={src_ip} destination_port={dst_port} unique_ports={unique_ports}/{self.MIN_DISTINCT_PORTS}"
                )

            # Sync top-level state
            if not run_id:
                state["alerted"] = active_target["alerted"]
                state["observations"] = active_target["observations"]
            else:
                state["last_run_id"] = run_id
                state["last_run_alerted"] = active_target["alerted"]

        return alert_created
                
    def clear_correlation_state(self, run_id: str = None):
        with self.correlation_lock:
            if run_id:
                for state in self.correlation_state.values():
                    if "run_states" in state and run_id in state["run_states"]:
                        del state["run_states"][run_id]
            else:
                self.correlation_state.clear()

live_inference_service = LiveInferenceService()