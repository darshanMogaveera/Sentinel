"""
Focused tests for backend-only multi-port simulation option in SENTINEL.
Tests port-range validation, input boundaries, and multi-port correlation handling.
"""
import unittest
import sys
import os
import time
from flask import Flask

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.database.db_models import db, Prediction, Alert
from backend.flask_api.routes.live_routes import validate_simulation_config
from live_extractor import LiveFlowExtractor


class TestMultiPortValidation(unittest.TestCase):
    """Test validation rules for simulation config."""

    def test_default_config_generates_default_range(self):
        """Empty config or minimal config should default to 12340-12349 on 127.0.0.1."""
        valid, msg, config = validate_simulation_config({})
        self.assertTrue(valid)
        self.assertEqual(config["dest_ip"], "127.0.0.1")
        self.assertEqual(config["dest_ports"], list(range(12340, 12350)))
        self.assertEqual(len(config["dest_ports"]), 10)

    def test_multi_port_flag_default(self):
        """multi_port: True should produce default 10 ports 12340-12349."""
        valid, msg, config = validate_simulation_config({"multi_port": True})
        self.assertTrue(valid)
        self.assertEqual(config["dest_ports"], list(range(12340, 12350)))

    def test_valid_custom_port_range(self):
        """Valid range 12340-12345 (6 ports) should succeed."""
        valid, msg, config = validate_simulation_config({
            "dest_ip": "127.0.0.1",
            "port_range_start": 12340,
            "port_range_end": 12345
        })
        self.assertTrue(valid)
        self.assertEqual(config["dest_ports"], [12340, 12341, 12342, 12343, 12344, 12345])

    def test_valid_port_range_string(self):
        """Valid port range string '12340-12349' should parse correctly."""
        valid, msg, config = validate_simulation_config({
            "port_range": "12340-12349"
        })
        self.assertTrue(valid)
        self.assertEqual(len(config["dest_ports"]), 10)

    def test_valid_explicit_dest_ports(self):
        """Explicit list of 10 ports should succeed."""
        ports = list(range(12340, 12350))
        valid, msg, config = validate_simulation_config({
            "dest_ports": ports
        })
        self.assertTrue(valid)
        self.assertEqual(config["dest_ports"], ports)

    def test_reject_invalid_dest_ip(self):
        """Only 127.0.0.1 is permitted as destination IP."""
        for invalid_ip in ["192.168.1.1", "0.0.0.0", "10.0.0.1", "localhost"]:
            valid, msg, _ = validate_simulation_config({"dest_ip": invalid_ip})
            self.assertFalse(valid, f"Expected rejection for IP: {invalid_ip}")
            self.assertIn("127.0.0.1", msg)

    def test_reject_more_than_11_ports(self):
        """Config requesting more than 11 ports must be rejected."""
        # 12 ports: 12340 to 12351
        valid, msg, _ = validate_simulation_config({
            "port_range_start": 12340,
            "port_range_end": 12351
        })
        self.assertFalse(valid)
        self.assertIn("maximum allowed limit of 11 ports", msg)

        # 12 ports via explicit list
        valid, msg, _ = validate_simulation_config({
            "dest_ports": list(range(1000, 1012))
        })
        self.assertFalse(valid)
        self.assertIn("maximum allowed limit of 11 ports", msg)

    def test_allow_exactly_11_ports(self):
        """Boundary test: exactly 11 ports should be accepted."""
        valid, msg, config = validate_simulation_config({
            "port_range_start": 12340,
            "port_range_end": 12350
        })
        self.assertTrue(valid)
        self.assertEqual(len(config["dest_ports"]), 11)

    def test_reject_inverted_port_range(self):
        """start_port > end_port must be rejected."""
        valid, msg, _ = validate_simulation_config({
            "port_range_start": 12350,
            "port_range_end": 12340
        })
        self.assertFalse(valid)
        self.assertIn("cannot be greater than", msg)

    def test_reject_out_of_bounds_ports(self):
        """Ports < 1 or > 65535 must be rejected."""
        valid, msg, _ = validate_simulation_config({"dest_port": 0})
        self.assertFalse(valid)

        valid, msg, _ = validate_simulation_config({"dest_port": 70000})
        self.assertFalse(valid)

        valid, msg, _ = validate_simulation_config({"dest_ports": [80, 443, 99999]})
        self.assertFalse(valid)

    def test_reject_empty_dest_ports(self):
        """Empty list of ports must be rejected."""
        valid, msg, _ = validate_simulation_config({"dest_ports": []})
        self.assertFalse(valid)


class TestExtractorMultiPortFiltering(unittest.TestCase):
    """Test that LiveFlowExtractor correctly filters and routes multi-port traffic."""

    class MockFlow:
        def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol=17, pkts=5):
            self.src_ip = src_ip
            self.dst_ip = dst_ip
            self.src_port = src_port
            self.dst_port = dst_port
            self.protocol = protocol
            self.bidirectional_packets = pkts
            self.bidirectional_bytes = pkts * 64
            self.bidirectional_duration_ms = 100
            self.src2dst_packets = pkts
            self.dst2src_packets = 0
            self.src2dst_bytes = pkts * 64
            self.dst2src_bytes = 0
            self.bidirectional_min_ps = 64
            self.bidirectional_mean_ps = 64.0
            self.bidirectional_stddev_ps = 0.0
            self.bidirectional_max_ps = 64
            self.src2dst_min_ps = 64
            self.src2dst_mean_ps = 64.0
            self.src2dst_stddev_ps = 0.0
            self.src2dst_max_ps = 64
            self.dst2src_min_ps = 0
            self.dst2src_mean_ps = 0.0
            self.dst2src_stddev_ps = 0.0
            self.dst2src_max_ps = 0
            self.bidirectional_min_piat_ms = 10
            self.bidirectional_mean_piat_ms = 10.0
            self.bidirectional_stddev_piat_ms = 0.0
            self.bidirectional_max_piat_ms = 10
            self.src2dst_min_piat_ms = 10
            self.src2dst_mean_piat_ms = 10.0
            self.src2dst_stddev_piat_ms = 0.0
            self.src2dst_max_piat_ms = 10
            self.dst2src_min_piat_ms = 0
            self.dst2src_mean_piat_ms = 0.0
            self.dst2src_stddev_piat_ms = 0.0
            self.dst2src_max_piat_ms = 0
            self.bidirectional_syn_packets = 0
            self.bidirectional_cwr_packets = 0
            self.bidirectional_ece_packets = 0
            self.bidirectional_urg_packets = 0
            self.bidirectional_ack_packets = 0
            self.bidirectional_psh_packets = 0
            self.bidirectional_rst_packets = 0
            self.bidirectional_fin_packets = 0
            self.src2dst_syn_packets = 0
            self.src2dst_cwr_packets = 0
            self.src2dst_ece_packets = 0
            self.src2dst_urg_packets = 0
            self.src2dst_ack_packets = 0
            self.src2dst_psh_packets = 0
            self.src2dst_rst_packets = 0
            self.src2dst_fin_packets = 0
            self.dst2src_syn_packets = 0
            self.dst2src_cwr_packets = 0
            self.dst2src_ece_packets = 0
            self.dst2src_urg_packets = 0
            self.dst2src_ack_packets = 0
            self.dst2src_psh_packets = 0
            self.dst2src_rst_packets = 0
            self.dst2src_fin_packets = 0

    def test_extractor_accepts_all_ports_in_range(self):
        extractor = LiveFlowExtractor()
        ports = list(range(12340, 12350))
        extractor.set_simulation_target("127.0.0.1", dest_ports=ports)

        # Flows on each of the 10 target ports should pass
        for port in ports:
            flow = self.MockFlow("127.0.0.1", "127.0.0.1", 50100, port)
            data = extractor.extract_features_from_nfstream(flow)
            self.assertIsNotNone(data, f"Flow on port {port} should pass target filter")
            self.assertEqual(len(data["vector"]), 69)

        # Flow on unrelated port should be filtered out
        unrelated_flow = self.MockFlow("127.0.0.1", "127.0.0.1", 50100, 9999)
        self.assertIsNone(extractor.extract_features_from_nfstream(unrelated_flow))


class TestMultiPortSimulationPipeline(unittest.TestCase):
    """Test full multi-port flow pipeline, feature extraction, and correlation threshold."""

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        from backend.database.db_models import db
        db.init_app(self.app)

        with self.app.app_context():
            db.create_all()

        self.app_ctx = self.app.app_context()
        self.app_ctx.push()

        from backend.services.packet_capture_service import packet_capture_service
        from backend.services.live_inference_service import live_inference_service
        self.packet_capture_service = packet_capture_service
        self.live_inference_service = live_inference_service
        self.packet_capture_service._app = self.app
        self.live_inference_service.clear_correlation_state()

    def tearDown(self):
        self.live_inference_service.clear_correlation_state()
        self.packet_capture_service._app = None
        self.app_ctx.pop()

    def test_ten_ports_trigger_correlation_alert(self):
        """10 distinct destination ports within 60s must satisfy MIN_DISTINCT_PORTS and trigger alert."""
        ports = list(range(12340, 12350))
        alert_results = []

        from backend.database.db_models import Prediction
        with self.app.app_context():
            # Create a base prediction in DB so save_alert has valid foreign key
            for idx, port in enumerate(ports):
                pred = Prediction(
                    source_ip="127.0.0.1",
                    dest_ip="127.0.0.1",
                    threat=True,
                    confidence=0.95,
                    threat_type="PortScan",
                    explanation=f'{{"dst_port": {port}}}'
                )
                db.session.add(pred)
                db.session.commit()

                pred_dict = {
                    "source_ip": "127.0.0.1",
                    "dest_ip": "127.0.0.1",
                    "protocol": 17,
                    "fwd_syn_packets": 0,
                    "fwd_rst_packets": 0,
                    "fwd_fin_packets": 0
                }
                explanation = {"dst_port": port}
                alerted = self.live_inference_service._handle_correlation(pred.id, pred_dict, explanation)
                alert_results.append(alerted)

        # First 9 ports should NOT trigger alert (unique_ports < 10)
        self.assertFalse(any(alert_results[:9]))
        # 10th distinct port should trigger the alert
        self.assertTrue(alert_results[9])

    def test_less_than_ten_ports_do_not_trigger_alert(self):
        """Fewer than 10 distinct destination ports (e.g. 5) must NOT trigger an alert."""
        ports = list(range(12340, 12345))
        from backend.database.db_models import Prediction

        with self.app.app_context():
            for port in ports:
                pred = Prediction(
                    source_ip="127.0.0.1",
                    dest_ip="127.0.0.1",
                    threat=True,
                    confidence=0.95,
                    threat_type="PortScan",
                    explanation=f'{{"dst_port": {port}}}'
                )
                db.session.add(pred)
                db.session.commit()

                pred_dict = {
                    "source_ip": "127.0.0.1",
                    "dest_ip": "127.0.0.1",
                    "protocol": 17,
                    "fwd_syn_packets": 0,
                    "fwd_rst_packets": 0,
                    "fwd_fin_packets": 0
                }
                explanation = {"dst_port": port}
                alerted = self.live_inference_service._handle_correlation(pred.id, pred_dict, explanation)
                self.assertFalse(alerted)

    def test_multi_port_pipeline_flow_ingestion(self):
        """Test that 10 distinct flows in range are ingested and yield predictions."""
        ports = list(range(12340, 12350))
        run_id = f"SIM-TEST-FLOWS-{int(time.time())}"
        self.packet_capture_service.reset_run(run_id, dest_ip="127.0.0.1", dest_ports=ports)

        extractor = self.packet_capture_service.extractor
        stats = self.packet_capture_service.run_stats[run_id]

        for port in ports:
            flow = TestExtractorMultiPortFiltering.MockFlow("127.0.0.1", "127.0.0.1", 54321, port, pkts=5)
            flow_data = extractor.extract_features_from_nfstream(flow)
            self.assertIsNotNone(flow_data)
            self.assertEqual(len(flow_data["vector"]), 69)
            stats["total_packets"] += 5
            extractor.expired_flows.append(flow_data)
            self.packet_capture_service._process_expired_flows(extractor, run_id, stats)

        self.assertEqual(stats["flushed_flows"], 10)
        self.assertEqual(stats["predictions"], 10)
        self.assertEqual(stats["inference_errors"], 0)


class TestMultiPortSimulationAPI(unittest.TestCase):
    """Test Flask API endpoint /api/live/simulate validation responses."""

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

        from backend.database.db_models import db
        from backend.flask_api.routes.live_routes import live_bp
        from backend.services.packet_capture_service import packet_capture_service

        db.init_app(self.app)
        self.app.register_blueprint(live_bp, url_prefix='/api/live')
        self.client = self.app.test_client()
        self.packet_capture_service = packet_capture_service

    def test_simulate_validation_rejections(self):
        # 1. Invalid IP
        res = self.client.post('/api/live/simulate', json={"dest_ip": "192.168.1.1"})
        self.assertEqual(res.status_code, 400)
        self.assertIn("only '127.0.0.1' is allowed", res.get_json()["error"])

        # 2. More than 11 ports
        res = self.client.post('/api/live/simulate', json={
            "dest_ip": "127.0.0.1",
            "port_range_start": 12340,
            "port_range_end": 12355
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("maximum allowed limit of 11 ports", res.get_json()["error"])

        # 3. Inverted range
        res = self.client.post('/api/live/simulate', json={
            "dest_ip": "127.0.0.1",
            "port_range_start": 12350,
            "port_range_end": 12340
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("cannot be greater than", res.get_json()["error"])

        # 4. Out of range port
        res = self.client.post('/api/live/simulate', json={
            "dest_ip": "127.0.0.1",
            "dest_port": 90000
        })
        self.assertEqual(res.status_code, 400)


if __name__ == "__main__":
    import time
    unittest.main()

