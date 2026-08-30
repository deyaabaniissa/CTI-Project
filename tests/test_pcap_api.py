from __future__ import annotations

import asyncio
import io
import os
import tempfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

os.environ["SITE_DATABASE_URL"] = "sqlite:///data/healthcare_cti_test.db"
os.environ.setdefault("XDG_CONFIG_HOME", str(Path(tempfile.gettempdir()) / "cti-scapy-config"))
os.environ.setdefault("XDG_CACHE_HOME", str(Path(tempfile.gettempdir()) / "cti-scapy-cache"))

import flask_app


class PcapApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = flask_app.app.test_client()
        with self.client.session_transaction() as session:
            session["admin_authenticated"] = True

    @staticmethod
    def capture_bytes() -> bytes:
        from scapy.all import DNS, DNSQR, IP, UDP, wrpcap

        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "capture.pcap"
            packet = (
                IP(src="10.10.0.5", dst="8.8.8.8")
                / UDP(sport=53000, dport=53)
                / DNS(rd=1, qd=DNSQR(qname="example.com"))
            )
            wrpcap(str(path), [packet])
            return path.read_bytes()

    def test_upload_keeps_model_and_cti_evidence_separate(self) -> None:
        async def fake_enrich(indicator: str, **_kwargs):
            return {
                "indicator": indicator,
                "type": "domain" if indicator == "example.com" else "ipv4",
                "verdict": "clean",
                "confidence": 0.0,
                "sources": {
                    "otx": {"available": True, "pulse_count": 0},
                    "virustotal": {"available": True, "malicious": 0, "total_engines": 70},
                },
            }

        with patch.object(flask_app.intelligence, "enrich_indicator", new=AsyncMock(side_effect=fake_enrich)):
            response = self.client.post(
                "/api/pcap/analyze",
                data={
                    "pcap": (io.BytesIO(self.capture_bytes()), "capture.pcap"),
                    "max_packets": "100",
                    "max_indicators": "5",
                },
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertEqual(payload["model"]["status"], "not_run")
        self.assertGreaterEqual(payload["capture_summary"]["public_indicator_count"], 2)
        self.assertTrue(payload["threat_intelligence"]["iot_indicators"])
        self.assertEqual(payload["asset_vulnerability"]["evidence"], [])
        self.assertEqual(payload["risk"]["score"], 0.0)

    def test_rejects_non_pcap_upload(self) -> None:
        response = self.client.post(
            "/api/pcap/analyze",
            data={"pcap": (io.BytesIO(b"not a capture"), "capture.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 422)

    def test_evaluation_context_uses_real_network_and_dependency_inputs(self) -> None:
        replay_row = flask_app.load_official_test_replay()[0]
        dashboard_log = flask_app.evaluation_dashboard_log(replay_row)
        self.assertEqual(
            dashboard_log["live_evidence_endpoint"],
            f"/api/evaluation-samples/{replay_row['sample_id']}/live-evidence",
        )
        self.assertEqual(dashboard_log["evidence_mode"], "pending_context")

        packages = flask_app.load_project_security_packages()
        self.assertEqual(
            [item["value"] for item in packages],
            [
                "PyPI:Flask:3.1.2",
                "npm:dompurify:3.4.12",
                "npm:nanoid:3.3.16",
                "npm:postcss:8.5.20",
            ],
        )

        async def fake_indicator(indicator: str, **_kwargs):
            return {
                "indicator": indicator,
                "type": "domain",
                "verdict": "clean",
                "confidence": 0.0,
                "sources": {},
                "coverage": {
                    "applicable_sources": ["otx", "virustotal"],
                    "configured_sources": ["otx", "virustotal"],
                    "available_sources": ["otx", "virustotal"],
                    "queried_sources": ["otx", "virustotal"],
                    "complete": True,
                },
            }

        async def fake_package(identifier: str, **_kwargs):
            return {
                "indicator": identifier,
                "type": "package",
                "verdict": "vulnerable",
                "confidence": 0.9,
                "sources": {},
                "coverage": {
                    "applicable_sources": ["osv", "nvd"],
                    "configured_sources": ["osv", "nvd"],
                    "available_sources": ["osv", "nvd"],
                    "queried_sources": ["osv", "nvd"],
                    "complete": True,
                },
            }

        with (
            patch.object(
                flask_app.intelligence,
                "enrich_indicator",
                new=AsyncMock(side_effect=fake_indicator),
            ),
            patch.object(
                flask_app.intelligence,
                "enrich_package",
                new=AsyncMock(side_effect=fake_package),
            ),
        ):
            evidence = asyncio.run(
                flask_app.enrich_family_capture_context(
                    "Benign",
                    1,
                    force_refresh=False,
                )
            )

        scopes = {item["provenance"]["evidence_scope"] for item in evidence}
        self.assertEqual(scopes, {"official_pcap_capture", "deployed_platform_dependency"})
        package = next(item for item in evidence if item["type"] == "package")
        self.assertEqual(package["indicator"], "PyPI:Flask:3.1.2")
        self.assertEqual(package["coverage"]["queried_sources"], ["osv", "nvd"])


if __name__ == "__main__":
    unittest.main()
