import unittest
import time
from flask import Flask
from backend.database.db_models import db
from backend.services.packet_capture_service import packet_capture_service
from live_extractor import LiveFlowExtractor


class MockFlow:
    """Mock NFStream flow object with standard flow metrics."""
    def __init__(
        self,
        src_ip="127.0.0.1",
        dst_ip="127.0.0.1",
        src_port=54321,
        dst_port=12345,
        protocol=6,
        bidirectional_packets=206,
        bidirectional_bytes=12000,
        bidirectional_duration_ms=1500,
        src2dst_packets=103,
        dst2src_packets=103,
        src2dst_bytes=6000,
        dst2src_bytes=6000,
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


class TestSimulationPipeline(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        db.init_app(self.app)

        with self.app.app_context():
            db.create_all()

        self.app_ctx = self.app.app_context()
        self.app_ctx.push()
        packet_capture_service._app = self.app

    def tearDown(self):
        self.app_ctx.pop()
        packet_capture_service._app = None

    def test_flow_arriving_after_traffic_generation_ends(self):
        """
        Regression Test: A completed flow from the simulated attack arriving
        after traffic generation has completed (simulation_state == PROCESSING)
        must be extracted, aggregated, and sent to live inference.
        """
        run_id = f"SIM-REGRESSION-{int(time.time())}"
        packet_capture_service.reset_run(run_id, dest_ip="127.0.0.1", dest_port=12345)

        stats = packet_capture_service.get_run_stats(run_id)
        self.assertEqual(stats["simulation_state"], "RUNNING")

        # Mark traffic finished (simulator thread done sending packets)
        packet_capture_service.mark_traffic_finished(run_id)
        stats = packet_capture_service.get_run_stats(run_id)
        self.assertEqual(stats["simulation_state"], "PROCESSING")

        # NFStream yields the simulated flow with 206 packets
        flow = MockFlow(
            src_ip="127.0.0.1",
            dst_ip="127.0.0.1",
            src_port=54321,
            dst_port=12345,
            bidirectional_packets=206
        )

        # Process through the pipeline
        extractor = packet_capture_service.extractor
        flow_data = extractor.extract_features_from_nfstream(flow)
        self.assertIsNotNone(flow_data, "Target flow was erroneously rejected by extractor")
        self.assertEqual(len(flow_data["vector"]), 69, "Features vector should have 69 CIC-IDS2017 features")

        # Ingest and flush
        stats_obj = packet_capture_service.run_stats[run_id]
        stats_obj["total_packets"] += flow.bidirectional_packets
        extractor.expired_flows.append(flow_data)
        packet_capture_service._process_expired_flows(extractor, run_id, stats_obj)

        updated_stats = packet_capture_service.get_run_stats(run_id)
        self.assertEqual(updated_stats["total_packets"], 206)
        self.assertEqual(updated_stats["flushed_flows"], 1)
        self.assertEqual(updated_stats["predictions"], 1)
        self.assertEqual(updated_stats["inference_errors"], 0)

    def test_flow_processed_even_if_state_completed(self):
        """
        Regression Test: Even if simulation_state transitioned to COMPLETED
        due to earlier timeouts, a matching flow yielded late by NFStream
        must NOT be discarded.
        """
        run_id = f"SIM-COMPLETED-{int(time.time())}"
        packet_capture_service.reset_run(run_id, dest_ip="127.0.0.1", dest_port=12345)
        packet_capture_service.mark_traffic_finished(run_id)

        stats_obj = packet_capture_service.run_stats[run_id]
        stats_obj["simulation_state"] = "COMPLETED"

        flow = MockFlow(
            src_ip="127.0.0.1",
            dst_ip="127.0.0.1",
            src_port=54321,
            dst_port=12345,
            bidirectional_packets=100
        )

        extractor = packet_capture_service.extractor
        flow_data = extractor.extract_features_from_nfstream(flow)
        self.assertIsNotNone(flow_data, "Matching flow should be extracted even if state is COMPLETED")

        stats_obj["total_packets"] += flow.bidirectional_packets
        extractor.expired_flows.append(flow_data)
        packet_capture_service._process_expired_flows(extractor, run_id, stats_obj)

        updated_stats = packet_capture_service.get_run_stats(run_id)
        self.assertEqual(updated_stats["flushed_flows"], 1)
        self.assertEqual(updated_stats["predictions"], 1)

    def test_non_matching_flow_filtered_out(self):
        """
        Ensure background or non-matching flows (e.g. random port 443)
        are rejected by the simulation filter and do not produce predictions.
        """
        run_id = f"SIM-NONMATCH-{int(time.time())}"
        packet_capture_service.reset_run(run_id, dest_ip="127.0.0.1", dest_port=12345)

        # Flow on unrelated IP and port
        unrelated_flow = MockFlow(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=55123,
            dst_port=443,
            bidirectional_packets=50
        )

        extractor = packet_capture_service.extractor
        flow_data = extractor.extract_features_from_nfstream(unrelated_flow)
        self.assertIsNone(flow_data, "Non-matching flow must return None")

        stats = packet_capture_service.get_run_stats(run_id)
        self.assertEqual(stats["flushed_flows"], 0)
        self.assertEqual(stats["predictions"], 0)

    def test_sentinel_ports_filtered_out(self):
        """
        Ensure Sentinel's own application ports (5000, 5173) are always filtered out.
        """
        extractor = LiveFlowExtractor()
        # Even without simulation target, Sentinel ports must be filtered
        flow_5000 = MockFlow(src_port=5000, dst_port=45678)
        flow_5173 = MockFlow(src_port=54321, dst_port=5173)

        self.assertIsNone(extractor.extract_features_from_nfstream(flow_5000))
        self.assertIsNone(extractor.extract_features_from_nfstream(flow_5173))

    def test_delayed_flow_emission(self):
        """
        Regression Test: Verify that when NFStream emits a flow with delay
        (e.g. 15 seconds after traffic ends on Windows loopback),
        the simulation remains in PROCESSING state, extracts and predicts
        the flow upon arrival, and then cleanly completes with non-zero counters.
        """
        run_id = f"SIM-DELAY-{int(time.time())}"
        packet_capture_service.reset_run(run_id, dest_ip="127.0.0.1", dest_port=12345)
        packet_capture_service.mark_traffic_finished(run_id)

        stats_obj = packet_capture_service.run_stats[run_id]

        # 12 seconds after traffic ends: flow has not arrived yet.
        # State MUST stay in PROCESSING, not prematurely completed with 0 counters.
        stats_obj["traffic_finished_time"] = time.time() - 12.0
        stats = packet_capture_service.get_run_stats(run_id)
        self.assertEqual(stats["simulation_state"], "PROCESSING", "Must not prematurely complete before flow arrives")
        self.assertEqual(stats["total_packets"], 0)
        self.assertEqual(stats["flushed_flows"], 0)

        # NFStream now emits the delayed flow (at t = 14s)
        delayed_flow = MockFlow(
            src_ip="127.0.0.1",
            dst_ip="127.0.0.1",
            src_port=54321,
            dst_port=12345,
            bidirectional_packets=206
        )

        extractor = packet_capture_service.extractor
        flow_data = extractor.extract_features_from_nfstream(delayed_flow)
        self.assertIsNotNone(flow_data)

        # Ingest flow into pipeline
        stats_obj["total_packets"] += delayed_flow.bidirectional_packets
        extractor.expired_flows.append(flow_data)
        packet_capture_service._process_expired_flows(extractor, run_id, stats_obj)
        stats_obj["last_flow_time"] = time.time()

        # Immediately after flow is ingested: stats are updated, state is still PROCESSING (grace buffer active)
        stats = packet_capture_service.get_run_stats(run_id)
        self.assertEqual(stats["total_packets"], 206)
        self.assertEqual(stats["flushed_flows"], 1)
        self.assertEqual(stats["predictions"], 1)
        self.assertEqual(stats["simulation_state"], "PROCESSING")

        # 2.5 seconds after flow arrived: grace buffer elapses and simulation transitions to COMPLETED
        stats_obj["last_flow_time"] = time.time() - 2.5
        completed_stats = packet_capture_service.get_run_stats(run_id)
        self.assertEqual(completed_stats["simulation_state"], "COMPLETED")
        self.assertEqual(completed_stats["total_packets"], 206)
        self.assertEqual(completed_stats["flushed_flows"], 1)
        self.assertEqual(completed_stats["predictions"], 1)

    def test_simulation_lifecycle_unflushed_timeout(self):
        """
        Verify that if no flows ever arrive, the simulation stays in PROCESSING
        until the full pending drain window (25s) elapses.
        """
        run_id = f"SIM-DRAIN-{int(time.time())}"
        packet_capture_service.reset_run(run_id, dest_ip="127.0.0.1", dest_port=12345)
        packet_capture_service.mark_traffic_finished(run_id)

        stats_obj = packet_capture_service.run_stats[run_id]

        # 10 seconds after finish: should still be PROCESSING
        stats_obj["traffic_finished_time"] = time.time() - 10.0
        stats = packet_capture_service.get_run_stats(run_id)
        self.assertEqual(stats["simulation_state"], "PROCESSING")

        # 20 seconds after finish: should still be PROCESSING
        stats_obj["traffic_finished_time"] = time.time() - 20.0
        stats = packet_capture_service.get_run_stats(run_id)
        self.assertEqual(stats["simulation_state"], "PROCESSING")

        # 26 seconds after finish (past max_pending_drain=25s): safely completes
        stats_obj["traffic_finished_time"] = time.time() - 26.0
        stats = packet_capture_service.get_run_stats(run_id)
        self.assertEqual(stats["simulation_state"], "COMPLETED")

    def test_capture_startup_failure_reporting(self):
        """
        Verify that attempting to start capture with an invalid interface
        raises RuntimeError immediately and does not leave capture running.
        """
        packet_capture_service.stop()
        with self.assertRaises((RuntimeError, ValueError)):
            packet_capture_service.start("NonExistentDevice_Invalid_Interface_12345")
        self.assertFalse(packet_capture_service.is_running)

    def test_frontend_interface_mapping_to_nfstream_source(self):
        """
        Verify that interface items map the raw Npcap device path
        (e.g. \\Device\\NPF_Loopback) as 'name', preserving the exact source string for NFStream.
        """
        from backend.flask_api.app import create_app
        app = create_app()
        with app.test_client() as client:
            res = client.get("/api/live/interfaces")
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertIn("interfaces", data)
            # Find loopback if present
            loopback = next((i for i in data["interfaces"] if "\\Device\\NPF_Loopback" in i["name"]), None)
            if loopback:
                self.assertEqual(loopback["name"], "\\Device\\NPF_Loopback")

    def test_simulation_run_id_association(self):
        """
        Verify that distinct simulation runs maintain isolated statistics
        and do not corrupt or overwrite each other.
        """
        run_1 = "SIM-RUN-1"
        run_2 = "SIM-RUN-2"

        packet_capture_service.reset_run(run_1, dest_ip="127.0.0.1", dest_port=12345)
        packet_capture_service.run_stats[run_1]["total_packets"] = 5
        packet_capture_service.run_stats[run_1]["predictions"] = 1

        packet_capture_service.reset_run(run_2, dest_ip="127.0.0.1", dest_port=80)
        self.assertEqual(packet_capture_service.current_run_id, run_2)
        self.assertEqual(packet_capture_service.get_run_stats(run_2)["total_packets"], 0)
        self.assertEqual(packet_capture_service.get_run_stats(run_1)["total_packets"], 5)

    def test_counter_updates_and_inference_error_handling(self):
        """
        Verify that if model inference raises an exception during flow processing,
        inference_errors counter increments while flushed_flows is still accurately counted.
        """
        from unittest.mock import patch
        run_id = f"SIM-ERR-{int(time.time())}"
        packet_capture_service.reset_run(run_id, dest_ip="127.0.0.1", dest_port=12345)

        flow = MockFlow(src_port=54321, dst_port=12345, bidirectional_packets=10)
        extractor = packet_capture_service.extractor
        flow_data = extractor.extract_features_from_nfstream(flow)
        extractor.expired_flows.append(flow_data)

        stats_obj = packet_capture_service.run_stats[run_id]
        stats_obj["total_packets"] += flow.bidirectional_packets

        with patch("backend.services.live_inference_service.live_inference_service.predict", side_effect=RuntimeError("Simulated Model Crash")):
            packet_capture_service._process_expired_flows(extractor, run_id, stats_obj)

        stats = packet_capture_service.get_run_stats(run_id)
        self.assertEqual(stats["total_packets"], 10)
        self.assertEqual(stats["flushed_flows"], 1)
        self.assertEqual(stats["predictions"], 0)
        self.assertEqual(stats["inference_errors"], 1)


if __name__ == "__main__":
    unittest.main()
