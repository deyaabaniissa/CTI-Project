import unittest

from cti.extraction import extract_indicators


class IndicatorExtractionTests(unittest.TestCase):
    def test_extracts_only_allowlisted_security_fields(self):
        values = extract_indicators(
            {
                "source_ip": "10.0.1.4",
                "destination_ip": "8.8.8.8",
                "url": "https://Example.com/path",
                "clinical_note": "See https://should-never-be-parsed.example",
            }
        )
        self.assertEqual([item.value for item in values], ["10.0.1.4", "8.8.8.8", "https://Example.com/path"])
        self.assertFalse(values[0].is_public)
        self.assertTrue(values[1].is_public)

    def test_deduplicates_same_indicator_from_multiple_fields(self):
        values = extract_indicators({"indicator": "Example.COM.", "domain": "example.com"})
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0].field, "indicator")

    def test_extracts_workbook_vulnerability_and_prefixed_hash_references(self):
        values = extract_indicators(
            {
                "threat_reference_id": "CVE-2020-1472",
                "file_hash": f"sha256:{'a' * 64}",
            }
        )
        self.assertEqual([(item.indicator_type, item.value) for item in values], [
            ("sha256", "a" * 64),
            ("cve", "CVE-2020-1472"),
        ])


if __name__ == "__main__":
    unittest.main()
