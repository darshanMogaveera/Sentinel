import threading
import time
import traceback
try:
    import nfstream
except Exception:
    nfstream = None

from live_extractor import LiveFlowExtractor
from backend.services.live_inference_service import live_inference_service
from backend.services.logging_service import logger_service


def normalize_and_resolve_interface(interface_name: str) -> str:
    """Resolve friendly label or Scapy name to a valid NFStream device name."""
    if not interface_name:
        return interface_name

    # Try direct Scapy conf lookup first
    try:
        from scapy.all import conf
        for iface in conf.ifaces.values():
            if (
                interface_name.lower() == getattr(iface, "name", "").lower()
                or interface_name.lower() == getattr(iface, "description", "").lower()
            ):
                net_name = getattr(iface, "network_name", None) or getattr(iface, "pcap_name", None)
                if net_name:
                    interface_name = net_name
                    break
    except Exception:
        pass

    # Collapse any double backslashes
    if interface_name.startswith('\\\\'):
        interface_name = interface_name.replace('\\\\', '\\')
    return interface_name


class PacketCaptureService:
    def __init__(self):
        self._running = False
        self._heartbeat_running = False
        self._thread = None
        self._heartbeat_thread = None
        self._interface = None
        self._app = None
        self._lock = threading.Lock()
        self._capture_ready = threading.Event()
        self._startup_error = None
        self._last_stopped_time = 0.0

        self.current_run_id = None
        self.extractor = None
        self.run_stats = {}

    def _get_empty_stats(self):
        return {
            "total_packets": 0,
            "flushed_flows": 0,
            "predictions": 0,
            "alerts": 0,
            "inference_errors": 0,
            "capture_errors": 0,
            "simulation_state": "IDLE"
        }

    def _get_initial_run_stats(self):
        return {
            "total_packets": 0,
            "flushed_flows": 0,
            "predictions": 0,
            "alerts": 0,
            "inference_errors": 0,
            "capture_errors": 0,
            "simulation_state": "RUNNING"
        }

    def _check_simulation_lifecycle(self, stats, extractor=None):
        if stats.get("simulation_state") == "PROCESSING":
            finished_time = stats.get("traffic_finished_time", 0)
            if finished_time <= 0:
                return

            ext = extractor or self.extractor
            idle_timeout = ext.idle_timeout if ext else 1.0
            now = time.time()

            has_flushed = stats.get("flushed_flows", 0) > 0
            has_pending = bool(ext.expired_flows) if ext else False

            if has_flushed:
                # Flow(s) have been flushed! Allow a brief 1.0s grace buffer after the last observed flow
                last_flow_time = stats.get("last_flow_time", finished_time)
                if (now - last_flow_time >= 1.0) and not has_pending:
                    stats["simulation_state"] = "COMPLETED"
            else:
                # Allow up to 25s before declaring completed if no flows arrived
                max_pending_drain = 25.0
                if (now - finished_time >= max_pending_drain) and not has_pending:
                    stats["simulation_state"] = "COMPLETED"

    @property
    def stats(self):
        with self._lock:
            if (
                self.current_run_id
                and self.current_run_id in self.run_stats
            ):
                stats = self.run_stats[self.current_run_id]
                self._check_simulation_lifecycle(stats, self.extractor)
                if self.current_run_id.startswith("SIM-"):
                    logger_service.logger.info(
                        f"[STAGE 9][{self.current_run_id}] Stats retrieved (poll): state={stats.get('simulation_state')} pkts={stats.get('total_packets')} flows={stats.get('flushed_flows')} preds={stats.get('predictions')} alerts={stats.get('alerts')} errs={stats.get('inference_errors')}"
                    )
                return stats.copy()

            return self._get_empty_stats()

    def get_run_stats(self, run_id: str):
        with self._lock:
            if run_id and run_id in self.run_stats:
                stats = self.run_stats[run_id]
                self._check_simulation_lifecycle(stats, self.extractor)
                logger_service.logger.info(
                    f"[STAGE 9][{run_id}] Stats retrieved: state={stats.get('simulation_state')} pkts={stats.get('total_packets')} flows={stats.get('flushed_flows')} preds={stats.get('predictions')} alerts={stats.get('alerts')} errs={stats.get('inference_errors')}"
                )
                return stats.copy()
            return self._get_empty_stats()

    def _clear_run_state(self):
        self.current_run_id = None
        self.extractor = None

    def reset_run(
        self,
        run_id: str,
        dest_ip: str = None,
        dest_port: int = None,
        dest_ports: list = None
    ):
        with self._lock:
            self.current_run_id = run_id
            self.extractor = LiveFlowExtractor(idle_timeout=1.0)
            self.run_stats[run_id] = self._get_initial_run_stats()

            if dest_ip and (dest_port or dest_ports):
                self.extractor.set_simulation_target(dest_ip, dest_port=dest_port, dest_ports=dest_ports)

        # Ensure correlation state for this run_id starts fresh
        live_inference_service.clear_correlation_state(run_id=run_id)
        logger_service.logger.info(
            f"[STAGE 1][{run_id}] Simulation state initialized: target={dest_ip} ports={dest_ports or dest_port}"
        )

    def mark_traffic_finished(self, run_id: str):
        with self._lock:
            if (
                run_id in self.run_stats
                and self.run_stats[run_id]["simulation_state"] == "RUNNING"
            ):
                self.run_stats[run_id]["simulation_state"] = "PROCESSING"
                self.run_stats[run_id]["traffic_finished_time"] = time.time()

    @property
    def is_running(self):
        return self._running

    @property
    def current_interface(self):
        return self._interface

    def start(self, interface: str, app=None):
        if self._running:
            raise ValueError("Capture is already running.")
        if not interface:
            raise ValueError("Interface must be explicitly provided.")

        resolved_interface = normalize_and_resolve_interface(interface)

        # Ensure previous thread is cleaned up
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

        # Windows Npcap settle time: give kernel driver a moment to release adapter handle
        since_stopped = time.time() - getattr(self, "_last_stopped_time", 0.0)
        if since_stopped < 0.6:
            time.sleep(0.6 - since_stopped)

        self._app = app

        with self._lock:
            self._interface = resolved_interface
            self._running = True
            self._heartbeat_running = True
            self._startup_error = None
            self._capture_ready.clear()

            live_run_id = f"LIVE-{int(time.time())}"
            self.current_run_id = live_run_id
            self.extractor = LiveFlowExtractor(idle_timeout=1.0)
            live_stats = self._get_empty_stats()
            live_stats["simulation_state"] = "IDLE"
            self.run_stats[live_run_id] = live_stats

        logger_service.logger.info(
            f"[STAGE 1][{live_run_id}] Capture thread starting on interface {resolved_interface!r}"
        )

        self._thread = threading.Thread(
            target=self._capture_loop,
            daemon=True
        )
        self._thread.start()

        # Wait up to 5 seconds for capture loop / NFStreamer to initialize
        ready = self._capture_ready.wait(timeout=5.0)
        if not ready or self._startup_error or not self._running:
            err = self._startup_error or "Timeout initializing capture interface"
            self.stop()
            raise RuntimeError(f"Failed to start packet capture on '{interface}': {err}")

        # Warmup: On Windows, NFStreamer spawns a multiprocessing child process
        # that takes ~1.5s to load C libraries and call activate_capture.
        # Settle 2.5s to ensure Npcap is actively capturing before returning.
        time.sleep(2.5)

        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True
        )
        self._heartbeat_thread.start()

        logger_service.logger.info(
            f"Packet capture started on interface {resolved_interface} with live run {live_run_id}"
        )

    def stop(self):
        if not self._running:
            return

        self._running = False
        
        # Shut down heartbeat
        self._heartbeat_running = False
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=1.0)
        self._heartbeat_thread = None

        # Terminate capture thread
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None

        self._last_stopped_time = time.time()
        logger_service.logger.info("Packet capture stopped.")

    def _heartbeat_loop(self):
        import socket
        while self._heartbeat_running:
            try:
                # Send discrete clock-tick packets from fresh ephemeral sockets
                # to advance NFStream's meter_tick without holding open a persistent flow
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(b"tick", ("127.0.0.1", 54321))
                sock.close()
            except Exception:
                pass
            time.sleep(1.5)

    def _capture_loop(self):
        try:
            logger_service.logger.info(
                f"_capture_loop: opening NFStreamer source={self._interface!r}"
            )
            # On Windows loopback, filter out background IDE TCP chatter so it doesn't block NFCache
            is_loopback = "loopback" in self._interface.lower()
            if is_loopback:
                bpf = "udp or portrange 12340-12350 or port 12345 or port 80 or port 443 or port 22 or port 21 or port 23 or port 8080 or port 1883"
            else:
                bpf = "not (port 5000 or port 5173)"

            streamer = nfstream.NFStreamer(
                source=self._interface,
                statistical_analysis=True,
                accounting_mode=0,
                bpf_filter=bpf,
                active_timeout=60,
                idle_timeout=1,
                snapshot_length=65535
            )
            logger_service.logger.info(
                f"[STAGE 2][{self.current_run_id}] NFStreamer successfully initialized on {self._interface!r}"
            )
            self._capture_ready.set()

            for flow in streamer:

                if not self._running:
                    break

                # Exclude internal clock ticker ports natively from ALL statistics, ML, and logs
                if flow.src_port in (54321, 55555) or flow.dst_port in (54321, 55555):
                    with self._lock:
                        run_id = self.current_run_id
                        stats = self.run_stats.get(run_id) if run_id else None
                        if stats:
                            self._check_simulation_lifecycle(stats, self.extractor)
                    continue

                with self._lock:
                    extractor = self.extractor
                    run_id = self.current_run_id
                    stats = self.run_stats.get(run_id) if run_id else None

                target_port = getattr(extractor, 'sim_target_port', None)
                target_ports = getattr(extractor, 'sim_target_ports', None)
                if target_ports is not None:
                    is_target_related = (
                        flow.src_port in target_ports or
                        flow.dst_port in target_ports
                    )
                else:
                    is_target_related = (
                        target_port is None
                        or flow.src_port == target_port
                        or flow.dst_port == target_port
                    )

                if not is_target_related:
                    with self._lock:
                        self._check_simulation_lifecycle(stats, extractor)
                    continue

                logger_service.logger.info(
                    f"[STAGE 4][{run_id}] NFStream emitted flow: src={flow.src_ip}:{flow.src_port} dst={flow.dst_ip}:{flow.dst_port} proto={flow.protocol} pkts={flow.bidirectional_packets}"
                )

                # Feature extraction handles filtering (simulation target & Sentinel ports)
                flow_data = extractor.extract_features_from_nfstream(flow)

                if flow_data:
                    logger_service.logger.info(
                        f"[STAGE 5][{run_id}] Target filter PASSED: src={flow.src_ip}:{flow.src_port} dst={flow.dst_ip}:{flow.dst_port}"
                    )
                    # Flow belongs to simulation run or active live monitoring
                    stats["total_packets"] += int(getattr(flow, "bidirectional_packets", 0) or 0)
                    extractor.expired_flows.append(flow_data)

                    if self._app:
                        with self._app.app_context():
                            self._process_expired_flows(extractor, run_id, stats)
                    else:
                        self._process_expired_flows(extractor, run_id, stats)

                    with self._lock:
                        stats["last_flow_time"] = time.time()
                else:
                    logger_service.logger.info(
                        f"[STAGE 5][{run_id}] Target filter REJECTED (target_port={target_port}): src={flow.src_ip}:{flow.src_port} dst={flow.dst_ip}:{flow.dst_port}"
                    )

                with self._lock:
                    self._check_simulation_lifecycle(stats, extractor)

        except Exception as e:
            with self._lock:
                self._startup_error = str(e)
                run_id = self.current_run_id
                if run_id and run_id in self.run_stats:
                    self.run_stats[run_id]["capture_errors"] += 1
                    self.run_stats[run_id]["last_error"] = str(e)
            self._running = False
            self._capture_ready.set()
            logger_service.logger.error(f"[STAGE 2][{run_id}] Capture error: {traceback.format_exc()}")

    def _process_expired_flows(self, extractor, run_id, stats):
        while True:
            with self._lock:
                if not extractor.expired_flows:
                    break
                flow_data = extractor.expired_flows.pop(0)

            features = flow_data["vector"]
            meta = flow_data["meta"]

            if len(features) == 69:
                logger_service.logger.info(
                    f"[STAGE 6][{run_id}] Feature vector produced: {len(features)} features (expected 69)"
                )
            else:
                logger_service.logger.error(
                    f"[STAGE 6][{run_id}] Feature extraction failure: produced {len(features)} features (expected 69)"
                )

            with self._lock:
                stats["flushed_flows"] += 1

            try:
                result = live_inference_service.predict(
                    features,
                    meta,
                    run_id=run_id
                )
                logger_service.logger.info(
                    f"[STAGE 7][{run_id}] Inference prediction: threat={result.get('threat')} type={result.get('threat_type')} conf={result.get('confidence', 0):.3f}"
                )
                pred_id = result.get('id')
                if pred_id:
                    logger_service.logger.info(
                        f"[STAGE 8][{run_id}] Persistence & correlation SUCCESS: id={pred_id} alerted={result.get('alerted')}"
                    )
                else:
                    logger_service.logger.error(
                        f"[STAGE 8][{run_id}] Persistence & correlation FAILED: prediction_id is None"
                    )
                with self._lock:
                    stats["predictions"] += 1
                    if result.get("alerted"):
                        stats["alerts"] += 1
            except Exception as e:
                with self._lock:
                    stats["inference_errors"] += 1
                logger_service.logger.error(f"[STAGE 7][{run_id}] Inference error on live flow: {e}")


packet_capture_service = PacketCaptureService()