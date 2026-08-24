from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from cti.db.session import create_database_engine, get_session_factory
from cti.db.site_persistence import SitePersistenceService


class SiteDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.previous_url = os.environ.get("SITE_DATABASE_URL")
        self.temp_dir = tempfile.TemporaryDirectory()
        database_path = Path(self.temp_dir.name) / "site.db"
        os.environ["SITE_DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
        get_session_factory.cache_clear()
        create_database_engine.cache_clear()
        self.service = SitePersistenceService(
            {
                "model_name": "test-catboost",
                "features": ["IAT", "Rate"],
                "metrics": {"balanced_accuracy": 0.93},
            },
            "test-model.joblib",
        )
        self.service.initialize()

    def tearDown(self) -> None:
        create_database_engine().dispose()
        get_session_factory.cache_clear()
        create_database_engine.cache_clear()
        if self.previous_url is None:
            os.environ.pop("SITE_DATABASE_URL", None)
        else:
            os.environ["SITE_DATABASE_URL"] = self.previous_url
        self.temp_dir.cleanup()

    def test_investigation_is_persisted_with_alert_and_prediction(self) -> None:
        event = {
            "asset_id": "test-gateway",
            "asset_criticality": 0.9,
            "src_ip": "8.8.8.8",
            "IAT": 10.0,
            "Rate": 5.0,
            "Number": 4,
            "Tot sum": 300,
        }
        result = {
            "investigation_id": "test-investigation-1",
            "prediction": {
                "model": "test-catboost",
                "predicted_family": "Recon",
                "confidence": 0.91,
                "features": {"IAT": 10.0, "Rate": 5.0},
            },
            "indicator_evidence": [],
            "risk_score": 78.0,
            "risk_level": "high",
            "is_threat": 1,
        }
        dashboard_log = {
            "log_id": "AI-TEST-1",
            "traffic_class": "Recon",
            "risk_level": "high",
            "risk_probability": 0.78,
            "is_threat": 1,
        }

        stored_id = self.service.persist(event, result, dashboard_log)
        status = self.service.status()
        alerts = self.service.list_alerts(10)
        investigations = self.service.list_dashboard_logs(10)

        self.assertEqual(stored_id, "test-investigation-1")
        self.assertEqual(status["backend"], "sqlite")
        self.assertEqual(status["counts"]["hospital_events"], 1)
        self.assertEqual(status["counts"]["model_predictions"], 1)
        self.assertEqual(status["counts"]["alerts"], 1)
        self.assertEqual(alerts[0]["event_id"], "test-investigation-1")
        self.assertEqual(investigations[0]["traffic_class"], "Recon")


if __name__ == "__main__":
    unittest.main()
