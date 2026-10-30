import unittest
import time
from unittest.mock import patch
from flask import Flask

from backend.database.db_models import db, Prediction, Alert
from backend.services.live_inference_service import LiveInferenceService


class TestCorrelationRunScoping(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        db.init_app(self.app)

        with self.app.app_context():
            db.create_all()

        self.service = LiveInferenceService.__new__(LiveInferenceService)
        self.service.correlation_state = {}
        import threading
        self.service.correlation_lock = threading.Lock()
        self.service.MIN_DISTINCT_PORTS = 10
        self.service.WINDOW_SECONDS = 60

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def _create_prediction(self, port, run_id=None):
        with self.app.app_context():
            pred = Prediction(
                source_ip="127.0.0.1",
                dest_ip="127.0.0.1",
                threat=True,
                confidence=0.99,
                threat_type="PortScan",
                explanation=f'{{"dst_port": {port}}}',
                run_id=run_id
            )
            db.session.add(pred)
            db.session.commit()
            pred_id = pred.id
            pred_dict = {
                "source_ip": "127.0.0.1",
                "dest_ip": "127.0.0.1",
                "protocol": 6,
                "fwd_syn_packets": 1,
                "fwd_rst_packets": 0,
                "fwd_fin_packets": 0,
                "run_id": run_id
            }
            explanation = {"dst_port": port}
            return pred_id, pred_dict, explanation

    def test_two_separate_qualifying_runs_each_save_alert(self):
        """
        Verify Requirement 5.1:
        Two separate qualifying simulation runs (e.g. SIM-RUN-1 and SIM-RUN-2)
        can each independently save an alert upon observing 10 distinct destination ports.
        """
        run1_id = "SIM-RUN-1"
        run2_id = "SIM-RUN-2"

        with self.app.app_context():
            # Run 1: Ports 12340 to 12349
            run1_results = []
            for port in range(12340, 12350):
                pred_id, pred_dict, explanation = self._create_prediction(port, run_id=run1_id)
                alerted = self.service._handle_correlation(pred_id, pred_dict, explanation)
                run1_results.append(alerted)

            # Ports 1-9 should not alert; port 10 must alert
            self.assertFalse(any(run1_results[:9]))
            self.assertTrue(run1_results[9])

            run1_alerts = Alert.query.all()
            self.assertEqual(len(run1_alerts), 1)
            pred1 = Prediction.query.get(run1_alerts[0].prediction_id)
            self.assertEqual(pred1.run_id, run1_id)

            # Run 2: Immediately following Run 1, without restarting backend or clearing state
            run2_results = []
            for port in range(12340, 12350):
                pred_id, pred_dict, explanation = self._create_prediction(port, run_id=run2_id)
                alerted = self.service._handle_correlation(pred_id, pred_dict, explanation)
                run2_results.append(alerted)

            # In Run 2, ports 1-9 must NOT alert (proving Run 2 does not falsely inherit Run 1's ports)
            self.assertFalse(any(run2_results[:9]))
            # Port 10 must alert for Run 2!
            self.assertTrue(run2_results[9])

            all_alerts = Alert.query.all()
            self.assertEqual(len(all_alerts), 2)
            alert_run_ids = {Prediction.query.get(a.prediction_id).run_id for a in all_alerts}
            self.assertEqual(alert_run_ids, {run1_id, run2_id})

    def test_repeated_qualifying_flows_within_one_run_do_not_create_duplicate_alerts(self):
        """
        Verify Requirement 5.2:
        Repeated qualifying flows within the same run do not create duplicate alerts.
        """
        run_id = "SIM-RUN-DEDUP"

        with self.app.app_context():
            # Send 10 distinct ports to trigger the first alert
            for port in range(12340, 12350):
                pred_id, pred_dict, explanation = self._create_prediction(port, run_id=run_id)
                self.service._handle_correlation(pred_id, pred_dict, explanation)

            alerts_after_10 = Alert.query.all()
            self.assertEqual(len(alerts_after_10), 1)

            # Send additional qualifying flows for the SAME run (e.g. ports 12350, 12351, and duplicate 12340)
            for extra_port in [12350, 12351, 12340, 12345]:
                pred_id, pred_dict, explanation = self._create_prediction(extra_port, run_id=run_id)
                alerted = self.service._handle_correlation(pred_id, pred_dict, explanation)
                self.assertFalse(alerted, f"Port {extra_port} within the same run created an unexpected duplicate alert!")

            alerts_final = Alert.query.all()
            self.assertEqual(len(alerts_final), 1, "Duplicate alerts were incorrectly saved for the same run!")

    def test_existing_correlation_window_behavior_remains_intact(self):
        """
        Verify Requirement 5.3:
        Existing 60-second sliding-window correlation behavior remains intact:
        1. When observations expire past WINDOW_SECONDS, the alerted state resets for live traffic.
        2. A new scan window can then trigger a fresh alert.
        """
        with self.app.app_context():
            # Phase 1: 10 distinct ports at T0 (no run_id, live traffic mode)
            base_time = 100000.0
            with patch('time.time', return_value=base_time):
                for port in range(12340, 12350):
                    pred_id, pred_dict, explanation = self._create_prediction(port, run_id=None)
                    alerted = self.service._handle_correlation(pred_id, pred_dict, explanation)

            self.assertEqual(Alert.query.count(), 1)

            # Phase 2: Flow 5 seconds later (within 60s window) is suppressed
            with patch('time.time', return_value=base_time + 5.0):
                pred_id, pred_dict, explanation = self._create_prediction(12355, run_id=None)
                alerted = self.service._handle_correlation(pred_id, pred_dict, explanation)
                self.assertFalse(alerted)

            self.assertEqual(Alert.query.count(), 1)

            # Phase 3: Time advances by 70 seconds past Phase 2 (> WINDOW_SECONDS=60).
            # Old observations expire; state['alerted'] resets to False.
            future_time = base_time + 5.0 + 65.0
            with patch('time.time', return_value=future_time):
                # Send 9 ports -> no alert yet
                for port in range(12340, 12349):
                    pred_id, pred_dict, explanation = self._create_prediction(port, run_id=None)
                    alerted = self.service._handle_correlation(pred_id, pred_dict, explanation)
                    self.assertFalse(alerted)

                self.assertEqual(Alert.query.count(), 1)

                # 10th distinct port in new window -> fresh alert!
                pred_id, pred_dict, explanation = self._create_prediction(12349, run_id=None)
                alerted = self.service._handle_correlation(pred_id, pred_dict, explanation)
                self.assertTrue(alerted)

            self.assertEqual(Alert.query.count(), 2)

    def test_subsequent_run_below_threshold_does_not_alert(self):
        """
        Verify that a subsequent run with fewer than 10 ports (e.g. 5 ports)
        does NOT alert, proving complete isolation between runs.
        """
        with self.app.app_context():
            # Run 1 qualifies with 10 ports
            for port in range(12340, 12350):
                pred_id, pred_dict, explanation = self._create_prediction(port, run_id="RUN-A")
                self.service._handle_correlation(pred_id, pred_dict, explanation)

            self.assertEqual(Alert.query.count(), 1)

            # Run 2 only scans 5 ports
            for port in range(12340, 12345):
                pred_id, pred_dict, explanation = self._create_prediction(port, run_id="RUN-B")
                alerted = self.service._handle_correlation(pred_id, pred_dict, explanation)
                self.assertFalse(alerted, "Run B alerted without reaching MIN_DISTINCT_PORTS!")

            self.assertEqual(Alert.query.count(), 1)


if __name__ == '__main__':
    unittest.main()
