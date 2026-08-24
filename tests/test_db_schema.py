import unittest
from datetime import datetime, timezone

from pydantic import ValidationError

from cti.db.models import Base
from cti.db.schemas import HospitalEventCreate, IndicatorCreate


class DatabaseSchemaTests(unittest.TestCase):
    def test_required_cti_tables_exist(self):
        expected = {
            "assets",
            "hospital_events",
            "indicators",
            "cti_lookup_results",
            "vulnerabilities",
            "asset_vulnerabilities",
            "model_predictions",
            "alerts",
            "alert_evidence",
            "audit_logs",
        }
        self.assertTrue(expected.issubset(Base.metadata.tables))

    def test_event_schema_rejects_invalid_port(self):
        with self.assertRaises(ValidationError):
            HospitalEventCreate(event_time=datetime.now(timezone.utc), destination_port=70000)

    def test_indicator_is_normalized(self):
        indicator = IndicatorCreate(indicator_type="domain", normalized_value=" Example.COM. ")
        self.assertEqual(indicator.normalized_value, "example.com")


if __name__ == "__main__":
    unittest.main()
