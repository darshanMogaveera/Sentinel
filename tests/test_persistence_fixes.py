import unittest
from unittest.mock import patch, MagicMock
from flask import Flask
from sqlalchemy.exc import SQLAlchemyError

import sys
from unittest.mock import MagicMock, patch
if 'xgboost' not in sys.modules:
    sys.modules['xgboost'] = MagicMock()
if 'xgboost.sklearn' not in sys.modules:
    sys.modules['xgboost.sklearn'] = MagicMock()

from backend.database.db_models import db, Prediction, Alert
from backend.services.database_service import DatabaseService

# Mock model loading during initial singleton instantiation
with patch('joblib.load') as mock_load:
    def fake_joblib_load(path):
        if "feature_names" in str(path):
            return [f"feat_{i}" for i in range(69)]
        return MagicMock()
    mock_load.side_effect = fake_joblib_load
    from backend.services.live_inference_service import LiveInferenceService


class TestDatabaseAndAlertPersistence(unittest.TestCase):
    def setUp(self):
        """Set up an isolated in-memory SQLite database and test service instances."""
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        db.init_app(self.app)

        with self.app.app_context():
            db.create_all()

        self.db_service = DatabaseService()

    def tearDown(self):
        """Clean up the isolated database."""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_save_prediction_success(self):
        """Verify successful prediction persistence and valid UUID returned."""
        with self.app.app_context():
            pred_data = {
                "source_ip": "192.168.1.10",
                "dest_ip": "10.0.0.1",
                "threat": True,
                "confidence": 0.95,
                "threat_type": "PortScan",
                "explanation": "Test explanation",
                "rf_prediction": 1,
                "if_prediction": 1,
                "run_id": "TEST-01"
            }
            pred_id = self.db_service.save_prediction(pred_data)
            self.assertIsNotNone(pred_id)
            self.assertIsInstance(pred_id, str)

            # Query database to confirm persisted record
            record = Prediction.query.get(pred_id)
            self.assertIsNotNone(record)
            self.assertEqual(record.source_ip, "192.168.1.10")
            self.assertEqual(record.dest_ip, "10.0.0.1")
            self.assertTrue(record.threat)
            self.assertEqual(record.threat_type, "PortScan")
            self.assertEqual(record.run_id, "TEST-01")

    def test_save_prediction_failure_and_rollback(self):
        """Verify prediction commit failure triggers rollback, logs error, and returns None."""
        with self.app.app_context():
            pred_data = {
                "source_ip": "192.168.1.11",
                "dest_ip": "10.0.0.2",
                "threat": False,
                "confidence": 0.1,
                "threat_type": "normal",
                "explanation": "Normal traffic",
                "rf_prediction": 0,
                "if_prediction": 1,
                "run_id": "TEST-FAIL"
            }

            with patch.object(db.session, 'commit', side_effect=SQLAlchemyError("Simulated DB lock")):
                with patch('backend.services.logging_service.logger_service.log_error') as mock_log:
                    pred_id = self.db_service.save_prediction(pred_data)
                    self.assertIsNone(pred_id)
                    mock_log.assert_called_once()
                    self.assertEqual(
                        mock_log.call_args[0][1].get("context"),
                        "DatabaseService.save_prediction"
                    )

            # Confirm session is healthy after rollback and no phantom prediction was saved
            count = Prediction.query.filter_by(source_ip="192.168.1.11").count()
            self.assertEqual(count, 0)

            # Confirm subsequent write works cleanly on the restored session
            ok_id = self.db_service.save_prediction(pred_data)
            self.assertIsNotNone(ok_id)

    def test_save_alert_success(self):
        """Verify successful alert persistence linked to prediction."""
        with self.app.app_context():
            pred_id = self.db_service.save_prediction({
                "source_ip": "192.168.1.20",
                "dest_ip": "10.0.0.5",
                "threat": True,
                "confidence": 0.99,
                "threat_type": "PortScan"
            })
            self.assertIsNotNone(pred_id)

            alert_id = self.db_service.save_alert(pred_id, severity="high")
            self.assertIsNotNone(alert_id)
            self.assertIsInstance(alert_id, str)

            # Query database to confirm alert
            alert = Alert.query.get(alert_id)
            self.assertIsNotNone(alert)
            self.assertEqual(alert.prediction_id, pred_id)
            self.assertEqual(alert.status, "active")
            self.assertEqual(alert.severity, "high")

    def test_save_alert_failure_and_rollback(self):
        """Verify alert commit failure triggers rollback, logs error, and returns None."""
        with self.app.app_context():
            pred_id = self.db_service.save_prediction({
                "source_ip": "192.168.1.30",
                "dest_ip": "10.0.0.8",
                "threat": True,
                "confidence": 0.98,
                "threat_type": "PortScan"
            })

            with patch.object(db.session, 'commit', side_effect=SQLAlchemyError("Disk write error")):
                with patch('backend.services.logging_service.logger_service.log_error') as mock_log:
                    alert_id = self.db_service.save_alert(pred_id, severity="high")
                    self.assertIsNone(alert_id)
                    mock_log.assert_called_once()
                    self.assertEqual(
                        mock_log.call_args[0][1].get("context"),
                        "DatabaseService.save_alert"
                    )

            # Confirm no phantom alert was saved
            count = Alert.query.filter_by(prediction_id=pred_id).count()
            self.assertEqual(count, 0)

    def test_handle_correlation_persistence_failure_allows_retry(self):
        """
        Verify that when save_alert fails during correlation:
        1. alert_created is False (no false success).
        2. state['alerted'] remains False.
        3. A subsequent eligible flow retries save_alert and succeeds.
        """
        service = LiveInferenceService.__new__(LiveInferenceService)
        service.correlation_state = {}
        import threading
        service.correlation_lock = threading.Lock()
        service.MIN_DISTINCT_PORTS = 10
        service.WINDOW_SECONDS = 60

        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.200"

        # Simulate 9 initial distinct ports (below threshold)
        for port in range(1, 10):
            explanation = {"dst_port": port}
            pred_result = {
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "protocol": 6,
                "fwd_syn_packets": 1
            }
            res = service._handle_correlation(f"pred-{port}", pred_result, explanation)
            self.assertFalse(res)

        # 10th distinct port reaches MIN_DISTINCT_PORTS threshold
        # Simulate save_alert FAILURE on this flow
        port_10_explanation = {"dst_port": 10}
        port_10_pred = {
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "protocol": 6,
            "fwd_syn_packets": 1
        }

        with patch('backend.services.live_inference_service.db_service.save_alert', return_value=None):
            alert_created = service._handle_correlation("pred-10", port_10_pred, port_10_explanation)
            # 1. Must NOT claim alert was created
            self.assertFalse(alert_created)
            # 2. State must NOT be permanently marked as alerted
            key = (src_ip, dst_ip)
            self.assertFalse(service.correlation_state[key]["alerted"])

        # Now an 11th distinct flow arrives. save_alert succeeds.
        port_11_explanation = {"dst_port": 11}
        port_11_pred = {
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "protocol": 6,
            "fwd_syn_packets": 1
        }

        with patch('backend.services.live_inference_service.db_service.save_alert', return_value="alert-real-uuid"):
            alert_created = service._handle_correlation("pred-11", port_11_pred, port_11_explanation)
            # 3. Must successfully trigger alert on retry
            self.assertTrue(alert_created)
            self.assertTrue(service.correlation_state[key]["alerted"])

        # Subsequent flows after successful alert should not re-alert (throttling preserved)
        port_12_explanation = {"dst_port": 12}
        port_12_pred = {
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "protocol": 6,
            "fwd_syn_packets": 1
        }
        with patch('backend.services.live_inference_service.db_service.save_alert') as mock_save:
            alert_created = service._handle_correlation("pred-12", port_12_pred, port_12_explanation)
            self.assertFalse(alert_created)
            mock_save.assert_not_called()

    def test_health_status_reflects_live_inference_service(self):
        """Verify /api/health/status reports healthy when live_inference_service.models_loaded is True."""
        from backend.flask_api.routes.health_routes import health_bp
        test_app = Flask(__name__)
        test_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        test_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        db.init_app(test_app)
        test_app.register_blueprint(health_bp)

        client = test_app.test_client()

        with test_app.app_context():
            db.create_all()
            with patch('backend.flask_api.routes.health_routes.live_inference_service') as mock_live:
                with patch('backend.flask_api.routes.health_routes.threat_service') as mock_legacy:
                    # Legacy models are None (unloaded), but production live model is loaded
                    mock_legacy.rf_model = None
                    mock_legacy.if_model = None
                    mock_live.models_loaded = True

                    res = client.get('/api/health/status')
                    self.assertEqual(res.status_code, 200)
                    data = res.get_json()
                    self.assertEqual(data.get("status"), "healthy")
                    self.assertTrue(data.get("models_loaded"))
                    self.assertTrue(data.get("database_connected"))


if __name__ == '__main__':
    unittest.main()

