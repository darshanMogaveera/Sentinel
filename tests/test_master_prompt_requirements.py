"""
Tests required by master prompt paragraph 4:
1.  Invalid capture interface/startup failure
2.  Correct mapping from frontend-selected interface to the actual NFStream source
4.  A real emitted flow passing the existing target filter
5.  A nonmatching flow being rejected by that filter (complementary)
6.  Accepted flow features reaching the production inference-service interface
9.  Capture exceptions being surfaced rather than falsely reporting successful monitoring
10. Existing persistence and correlation behavior remaining intact
Tests 3, 7, 8 already covered by test_simulation_pipeline.py.
"""
import unittest
import math
import time
from unittest.mock import patch
from flask import Flask
from backend.database.db_models import db
from backend.services.packet_capture_service import packet_capture_service
from live_extractor import LiveFlowExtractor


class MockFlow:
    def __init__(
        self,
        src_ip="127.0.0.1",
        dst_ip="127.0.0.1",
        src_port=54321,
        dst_port=12345,
        protocol=17,
        bidirectional_packets=5,
        bidirectional_bytes=320,
        bidirectional_duration_ms=500,
        src2dst_packets=5,
        dst2src_packets=0,
        src2dst_bytes=320,
        dst2src_bytes=0,
        **kwargs
    ):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.bidirectional_packets = bidirectional_packets
        self.bidirectional_bytes = bidirectional_bytes
        self.bidirectional_duration_ms = bidirectional_duration_ms
        self.src2dst_packets = src2dst_packets
        self.dst2src_packets = dst2src_packets
        self.src2dst_bytes = src2dst_bytes
        self.dst2src_bytes = dst2src_bytes
        for k, v in kwargs.items():
            setattr(self, k, v)


class TestMasterPromptRequirements(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        self.app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        db.init_app(self.app)
        with self.app.app_context():
            db.create_all()
        self.app_ctx = self.app.app_context()
        self.app_ctx.push()
        packet_capture_service._app = self.app
        if packet_capture_service.is_running:
            packet_capture_service.stop()

    def tearDown(self):
        if packet_capture_service.is_running:
            packet_capture_service.stop()
        packet_capture_service._app = None
        self.app_ctx.pop()

    # --- Test 1 ---
    def test_invalid_interface_raises_error_and_stops_cleanly(self):
        """Req 1: Invalid interface => RuntimeError/ValueError, is_running stays False."""
        with self.assertRaises((RuntimeError, ValueError)):
            packet_capture_service.start("TOTALLY_INVALID_DEVICE_99999")
        self.assertFalse(packet_capture_service.is_running)

    # --- Test 2 ---
    def test_interfaces_endpoint_returns_nfstream_valid_paths(self):
        """Req 2: /api/live/interfaces must return NFStream-valid single-backslash paths."""
        from backend.flask_api.app import create_app
        from nfstream.streamer import is_interface
        test_app = create_app()
        with test_app.test_client() as client:
            res = client.get("/api/live/interfaces")
            self.assertEqual(res.status_code, 200)
            ifaces = res.get_json()["interfaces"]
            self.assertGreater(len(ifaces), 0)
            for iface in ifaces:
                name = iface["name"]
                result = is_interface(name)
                self.assertIsNotNone(result, f"NFStream rejected interface {name!r}")
                if name.startswith("\\"):
                    self.assertFalse(name.startswith("\\\\"), f"Double-backslash path returned: {name!r}")
                self.assertTrue(iface.get("nfstream_valid", False), f"{name!r} nfstream_valid=False")

    # --- Test 4 ---
    def test_matching_loopback_flow_passes_filter(self):
        """Req 4: Matching loopback flow passes filter, produces 69 finite features."""
        extractor = LiveFlowExtractor(idle_timeout=1.0)
        extractor.set_simulation_target("127.0.0.1", 12345)
        flow = MockFlow()
        result = extractor.extract_features_from_nfstream(flow)
        self.assertIsNotNone(result)
        self.assertEqual(len(result["vector"]), 69)
        for i, v in enumerate(result["vector"]):
            self.assertTrue(math.isfinite(v), f"Feature[{i}]={v} is non-finite")

    # --- Test 5 ---
    def test_nonmatching_flow_rejected_by_filter(self):
        """Req 5: Non-matching flow returns None from filter."""
        extractor = LiveFlowExtractor(idle_timeout=1.0)
        extractor.set_simulation_target("127.0.0.1", 12345)
        unrelated = MockFlow(src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=12000, dst_port=443)
        self.assertIsNone(extractor.extract_features_from_nfstream(unrelated))

    # --- Test 6 ---
    def test_accepted_flow_features_reach_inference_service(self):
        """Req 6: 69-feature vector from extractor is accepted by live_inference_service.predict()."""
        from backend.services.live_inference_service import live_inference_service
        extractor = LiveFlowExtractor(idle_timeout=1.0)
        extractor.set_simulation_target("127.0.0.1", 12345)
        flow = MockFlow(bidirectional_packets=5, bidirectional_bytes=320, bidirectional_duration_ms=500)
        flow_data = extractor.extract_features_from_nfstream(flow)
        self.assertIsNotNone(flow_data)
        self.assertTrue(live_inference_service.models_loaded)
        result = live_inference_service.predict(flow_data["vector"], flow_data["meta"], run_id="TEST-REQ6")
        self.assertIn("threat", result)
        self.assertIn("confidence", result)
        self.assertIsInstance(result["confidence"], float)
        self.assertIn(result["threat_type"], ["none", "BENIGN", "PortScan", "PORTSCAN"])

    # --- Test 9 ---
    def test_capture_exception_surfaced_not_silently_suppressed(self):
        """Req 9: Capture with bad interface must raise, not silently report 'active'."""
        if packet_capture_service.is_running:
            packet_capture_service.stop()
        bad = "\\\\BadDevice\\\\INVALID_XYZ"
        with self.assertRaises((RuntimeError, ValueError)):
            packet_capture_service.start(bad)
        self.assertFalse(packet_capture_service.is_running)

    # --- Test 10 ---
    def test_persistence_and_correlation_intact(self):
        """Req 10: Full flow -> inference -> persistence -> correlation runs without exception."""
        from backend.services.live_inference_service import live_inference_service
        extractor = LiveFlowExtractor(idle_timeout=1.0)
        extractor.set_simulation_target("127.0.0.1", 12345)
        flow = MockFlow(bidirectional_packets=10, bidirectional_bytes=640, bidirectional_duration_ms=1000)
        flow_data = extractor.extract_features_from_nfstream(flow)
        self.assertIsNotNone(flow_data)
        with patch.object(live_inference_service.model, "predict_proba", return_value=[[0.02, 0.98]]):
            with patch.object(live_inference_service.label_encoder, "inverse_transform", return_value=["PortScan"]):
                result = live_inference_service.predict(flow_data["vector"], flow_data["meta"], run_id="TEST-CORR", skip_correlation=False)
        self.assertTrue(result["threat"])
        self.assertEqual(result["threat_type"], "PortScan")


if __name__ == "__main__":
    unittest.main(verbosity=2)
