import unittest
from uuid import uuid4

import pandas as pd

from cti.db.importer import create_event_rows


class StaticImporterTests(unittest.TestCase):
    def test_event_rows_keep_static_label_and_private_ip(self):
        frame = pd.DataFrame(
            [
                {
                    "event_id": "SYS-000001",
                    "event_time": "2026-01-01T00:47:51",
                    "event_source": "hospital_system_device_logs.xlsx",
                    "log_type": "system_device",
                    "source_ip": "10.0.1.172",
                    "destination_ip": "",
                    "source_port": 50000,
                    "dest_port": 443,
                    "protocol": "HTTPS",
                    "action": "Network Port Scan",
                    "device_type": "Core Router",
                    "status": "Blocked",
                    "severity": "High",
                    "label": 0,
                }
            ]
        )
        batch = type("Batch", (), {"id": uuid4()})()
        asset = type("Asset", (), {"id": uuid4()})()
        row = create_event_rows(frame, batch, asset)[0]
        self.assertEqual(row["dataset_label"], 0)
        self.assertEqual(row["source_ip"], "10.0.1.172")
        self.assertEqual(row["traffic_type"], "Network Port Scan")
        self.assertEqual(row["destination_port"], 443)


if __name__ == "__main__":
    unittest.main()
