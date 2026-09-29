import unittest
from io import StringIO
from pathlib import Path
from detections import detect, load_events

SAMPLE = Path(__file__).resolve().parents[1] / "data/sample_events.csv"

class DetectionTests(unittest.TestCase):
    def test_expected_alerts(self):
        alerts = detect(load_events(SAMPLE))
        self.assertEqual(alerts.rule.value_counts().to_dict(), {
            "Failed login burst": 1, "Successful login after failures": 1,
            "Reported phishing": 2, "Blocked malware": 1,
        })
    def test_threshold_changes_results(self):
        alerts = detect(load_events(SAMPLE), threshold=6)
        self.assertNotIn("Failed login burst", alerts.rule.tolist())
        self.assertNotIn("Successful login after failures", alerts.rule.tolist())
    def test_invalid_schema(self):
        with self.assertRaisesRegex(ValueError, "Missing columns"):
            load_events(StringIO("timestamp,event_id\n2026-01-01T00:00:00Z,E1"))
    def test_duplicate_ids(self):
        events = SAMPLE.read_text().splitlines()
        with self.assertRaisesRegex(ValueError, "unique"):
            load_events(StringIO("\n".join([events[0], events[1], events[1]])))

if __name__ == "__main__":
    unittest.main()
