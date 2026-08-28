import unittest

from cti.reporting import build_recommended_actions, summarize_provider_evidence


STATES = {
    provider: {"configured": True}
    for provider in ("otx", "virustotal", "osv", "nvd")
}


class ProviderReportTests(unittest.TestCase):
    def test_report_always_contains_all_four_providers(self):
        evidence = [
            {
                "indicator": "example.test",
                "type": "domain",
                "coverage": {
                    "applicable_sources": ["otx", "virustotal"],
                    "queried_sources": ["otx", "virustotal"],
                    "available_sources": ["otx", "virustotal"],
                },
                "sources": {
                    "otx": {"available": True, "pulse_count": 2, "reputation": 1},
                    "virustotal": {
                        "available": True,
                        "malicious": 4,
                        "suspicious": 1,
                        "harmless": 20,
                        "total_engines": 40,
                    },
                },
            }
        ]
        rows = summarize_provider_evidence(evidence, STATES)
        self.assertEqual([row["provider_id"] for row in rows], ["otx", "virustotal", "osv", "nvd"])
        self.assertEqual(rows[0]["status"], "available")
        self.assertEqual(rows[1]["status"], "available")
        self.assertEqual(rows[2]["status"], "not_applicable")
        self.assertEqual(rows[3]["status"], "not_applicable")

    def test_ioc_recommendation_is_linked_to_provider_and_log(self):
        provider_rows = summarize_provider_evidence(
            [
                {
                    "indicator": "bad.example",
                    "type": "domain",
                    "coverage": {
                        "applicable_sources": ["otx", "virustotal"],
                        "queried_sources": ["otx", "virustotal"],
                        "available_sources": ["otx", "virustotal"],
                    },
                    "sources": {
                        "otx": {"available": True, "pulse_count": 3},
                        "virustotal": {"available": True, "malicious": 5, "total_engines": 60},
                    },
                }
            ],
            STATES,
        )
        actions = build_recommended_actions(
            {"device_type": "Firewall", "department": "IT"},
            {
                "is_threat": 1,
                "probability": 0.92,
                "final_classification": "threat",
                "rule_assessment": {"attack_type": "command_and_control", "rule_id": "SYS-005", "reason": "DNS anomaly"},
            },
            {"indicator": "bad.example", "type": "domain", "verdict": "malicious"},
            provider_rows,
        )
        self.assertIn("bad.example", actions[0]["action"])
        self.assertEqual(actions[0]["evidence_sources"], ["AlienVault OTX", "VirusTotal"])
        self.assertIn("IT", actions[0]["problem"])

    def test_nvd_required_action_is_preserved(self):
        provider_rows = summarize_provider_evidence(
            [
                {
                    "indicator": "CVE-2020-1472",
                    "type": "cve",
                    "coverage": {
                        "applicable_sources": ["osv", "nvd"],
                        "queried_sources": ["osv", "nvd"],
                        "available_sources": ["osv", "nvd"],
                    },
                    "sources": {
                        "osv": {"available": True, "found": True, "id": "CVE-2020-1472"},
                        "nvd": {
                            "available": True,
                            "found": True,
                            "records": [
                                {
                                    "cve_id": "CVE-2020-1472",
                                    "cvss": 10.0,
                                    "severity": "CRITICAL",
                                    "known_exploited": True,
                                    "required_action": "Apply updates per vendor instructions.",
                                }
                            ],
                        },
                    },
                }
            ],
            STATES,
        )
        actions = build_recommended_actions(
            {"device_type": "Domain Controller", "department": "IT"},
            {
                "is_threat": 0,
                "probability": 0.4,
                "final_classification": "suspicious",
                "rule_assessment": {"attack_type": "none", "rule_id": "SYS-100", "reason": "Routine event"},
            },
            {"indicator": "CVE-2020-1472", "type": "cve", "verdict": "vulnerable"},
            provider_rows,
        )
        self.assertIn("Apply updates per vendor instructions.", actions[0]["action"])
        self.assertEqual(actions[0]["evidence_sources"], ["OSV", "NIST NVD"])

    def test_provider_failure_preserves_http_diagnostics(self):
        rows = summarize_provider_evidence(
            [
                {
                    "indicator": "CVE-2021-44228",
                    "type": "cve",
                    "coverage": {
                        "applicable_sources": ["osv", "nvd"],
                        "queried_sources": ["osv", "nvd"],
                        "available_sources": ["nvd"],
                    },
                    "sources": {
                        "osv": {
                            "available": False,
                            "error": "HTTP 429: rate limited",
                            "error_type": "http_error",
                            "http_status": 429,
                        },
                        "nvd": {"available": True, "found": False, "records": []},
                    },
                }
            ],
            STATES,
        )
        osv = next(row for row in rows if row["provider_id"] == "osv")
        self.assertEqual(osv["status"], "unavailable")
        self.assertIn("HTTP 429", osv["result"])
        self.assertEqual(osv["observations"][0]["metrics"]["http_status"], 429)


if __name__ == "__main__":
    unittest.main()
