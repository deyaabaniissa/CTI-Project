import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from cti.intelligence import ThreatIntelligenceService, classify_indicator, is_public_indicator


class IndicatorTests(unittest.TestCase):
    def test_indicator_classification(self):
        self.assertEqual(classify_indicator("8.8.8.8"), ("8.8.8.8", "ipv4"))
        self.assertEqual(classify_indicator("Example.COM."), ("example.com", "domain"))
        self.assertEqual(classify_indicator("a" * 64), ("a" * 64, "sha256"))
        self.assertEqual(classify_indicator(f"sha256:{'B' * 64}"), ("b" * 64, "sha256"))
        self.assertEqual(classify_indicator("cve-2020-1472"), ("CVE-2020-1472", "cve"))
        self.assertEqual(classify_indicator("ghsa-e0c5-dae9-519a"), ("GHSA-E0C5-DAE9-519A", "ghsa"))

    def test_private_addresses_are_not_shared(self):
        self.assertFalse(is_public_indicator("10.16.120.44", "ipv4"))
        self.assertTrue(is_public_indicator("8.8.8.8", "ipv4"))


class IntelligenceRoutingTests(unittest.IsolatedAsyncioTestCase):
    async def test_cve_routes_to_osv_and_nvd(self):
        with tempfile.TemporaryDirectory() as directory:
            service = ThreatIntelligenceService(Path(directory))
            service._lookup_osv_reference = AsyncMock(
                return_value={
                    "available": True,
                    "found": True,
                    "id": "CVE-2020-1472",
                    "aliases": ["CVE-2020-1472"],
                }
            )
            service._lookup_nvd = AsyncMock(
                return_value=[
                    {
                        "cve_id": "CVE-2020-1472",
                        "cvss": 10.0,
                        "severity": "CRITICAL",
                        "known_exploited": True,
                    }
                ]
            )
            result = await service.enrich_indicator("CVE-2020-1472")
            self.assertEqual(result["verdict"], "vulnerable")
            self.assertGreaterEqual(result["confidence"], 0.9)
            self.assertEqual(result["coverage"]["applicable_sources"], ["osv", "nvd"])
            service._lookup_osv_reference.assert_awaited_once()
            service._lookup_nvd.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
