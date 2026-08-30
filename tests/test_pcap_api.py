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

    def test_evaluation_rows_do_not_claim_capture_or_dependency_context(self) -> None:
        replay_row = flask_app.load_official_test_replay()[0]
        dashboard_log = flask_app.evaluation_dashboard_log(replay_row)
        self.assertEqual(
            dashboard_log["live_evidence_endpoint"],
            f"/api/evaluation-samples/{replay_row['sample_id']}/live-evidence",
        )
        self.assertEqual(dashboard_log["evidence_mode"], "not_applicable")
        self.assertEqual(dashboard_log["indicator_evidence"], [])
        self.assertIn("no attributable indicator", dashboard_log["intel_verdict"])

    def test_context_catalog_remains_separate_from_evaluation_rows(self) -> None:

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
        self.assertTrue(all(item["provenance"]["attributable_to_log"] is False for item in evidence))
        package = next(item for item in evidence if item["type"] == "package")
        self.assertEqual(package["indicator"], "PyPI:Flask:3.1.2")
        self.assertEqual(package["coverage"]["queried_sources"], ["osv", "nvd"])

    def test_false_positive_evaluation_never_recommends_containment(self) -> None:
        actions = flask_app.evaluation_recommendations(
            {
                "true_family": "Benign",
                "predicted_family": "Spoofing",
                "correct": False,
                "confidence": 0.495,
                "risk_level": "medium",
            }
        )

        combined_actions = " ".join(item["action"] for item in actions).lower()
        self.assertIn("false-positive", combined_actions)
        self.assertIn("do not initiate containment", combined_actions)
        self.assertNotIn("isolate the suspected", combined_actions)
        self.assertNotIn("temporary source blocking", combined_actions)

    def test_correct_benign_evaluation_has_no_incident_response_action(self) -> None:
        actions = flask_app.evaluation_recommendations(
            {
                "true_family": "Benign",
                "predicted_family": "Benign",
                "correct": True,
                "confidence": 0.99,
                "risk_level": "low",
            }
        )

        self.assertIn("No incident-response containment", actions[0]["action"])

    def test_evaluation_live_evidence_always_bypasses_cache(self) -> None:
        replay_row = flask_app.load_official_test_replay()[0]
        connectivity = {
            "checked_at": "2026-08-30T00:00:00+00:00",
            "all_four_connected": True,
        }
        with (
            patch.object(
                flask_app,
                "run_provider_connectivity_check",
                return_value=connectivity,
            ) as connectivity_check,
            patch.object(
                flask_app,
                "enrich_family_capture_context",
                new=AsyncMock(return_value=[]),
            ) as enrich_context,
        ):
            response = self.client.post(
                f"/api/evaluation-samples/{replay_row['sample_id']}/live-evidence",
                json={"force_refresh": False},
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertFalse(payload["live_query"])
        self.assertTrue(payload["connectivity_check"])
        self.assertFalse(payload["provider_findings_used_as_evidence"])
        self.assertFalse(payload["cache_used"])
        self.assertEqual(payload["evidence_mode"], "connectivity_only")
        self.assertEqual(payload["indicator_evidence"], [])
        self.assertFalse(payload["risk_adjustment_applied"])
        connectivity_check.assert_called_once_with(force_refresh=True)
        enrich_context.assert_not_awaited()

    def test_persisted_report_live_evidence_is_fresh_and_not_saved(self) -> None:
        investigation_id = "report-live-123"
        stored_log = {
            "investigation_id": investigation_id,
            "source_ip": "8.8.8.8",
            "destination_target": "example.com",
            "features": {},
            "indicator_evidence": [{
                "indicator": "context.example",
                "provenance": {"attributable_to_log": False},
            }],
        }
        states = {
            provider: {
                "configured": True,
                "status": "live",
                "last_success": "2026-08-30T00:00:00+00:00",
                "last_error": None,
            }
            for provider in ("otx", "virustotal", "osv", "nvd")
        }
        with (
            patch.object(
                flask_app.database,
                "list_dashboard_logs",
                return_value=[stored_log],
            ),
            patch.object(
                flask_app,
                "enrich_event",
                new=AsyncMock(return_value=[]),
            ) as enrich_event,
            patch.object(
                flask_app.intelligence,
                "status",
                return_value={"sources": states},
            ),
        ):
            response = self.client.post(
                f"/api/investigations/{investigation_id}/live-evidence",
                json={"force_refresh": False},
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertTrue(payload["live_query"])
        self.assertFalse(payload["cache_used"])
        self.assertEqual(payload["evidence_mode"], "connectivity_only")
        self.assertTrue(enrich_event.await_args.kwargs["force_refresh"])
        queried_event = enrich_event.await_args.args[0]
        self.assertNotIn("context.example", queried_event["indicators"])

    def test_context_only_cti_does_not_change_model_probability(self) -> None:
        result = flask_app.live_fused_risk(
            {"attack_probability": 0.5657},
            [{
                "verdict": "malicious",
                "confidence": 1.0,
                "provenance": {"attributable_to_log": False},
            }],
        )

        self.assertFalse(result["applied"])
        self.assertEqual(result["score"], 56.57)
        self.assertEqual(result["cti_score"], 0.0)
        self.assertIn("context-only evidence", result["reason"])
        self.assertIn("56.57%", result["reason"])

    def test_attributable_live_cti_updates_fused_risk(self) -> None:
        result = flask_app.live_fused_risk(
            {
                "attack_probability": 0.50,
                "asset_criticality": 0.80,
            },
            [{
                "verdict": "malicious",
                "confidence": 0.80,
                "provenance": {"attributable_to_log": True},
            }],
        )

        self.assertTrue(result["applied"])
        self.assertEqual(result["score"], 62.0)
        self.assertEqual(result["level"], "high")
        self.assertEqual(result["cti_score"], 0.8)
        self.assertIn("Live fused risk: 62.00%", result["reason"])


if __name__ == "__main__":
    unittest.main()
