from __future__ import annotations

import tempfile
import os
import unittest
from pathlib import Path

os.environ.setdefault("XDG_CONFIG_HOME", str(Path(tempfile.gettempdir()) / "cti-scapy-config"))
os.environ.setdefault("XDG_CACHE_HOME", str(Path(tempfile.gettempdir()) / "cti-scapy-cache"))

from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP, wrpcap
from scapy.layers.http import HTTP, HTTPRequest

from cti.pcap import extract_pcap_indicators


class PcapExtractionTests(unittest.TestCase):
    def test_extracts_attributable_public_and_private_indicators(self) -> None:
        packets = [
            Ether()
            / IP(src="192.168.10.5", dst="8.8.8.8")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.com")),
            Ether()
            / IP(src="192.168.10.5", dst="93.184.216.34")
            / TCP(sport=51000, dport=80)
            / HTTP()
            / HTTPRequest(Method=b"GET", Host=b"example.com", Path=b"/status"),
            Ether()
            / IP(src="192.168.10.5", dst="239.255.255.250")
            / UDP(sport=1900, dport=1900),
            Ether()
            / IP(src="192.168.10.5", dst="192.168.10.1")
            / UDP(sport=53001, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="1.10.168.192.in-addr.arpa")),
        ]
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "sample.pcap"
            wrpcap(str(capture), packets)
            result = extract_pcap_indicators(capture)

        by_value = {item["value"]: item for item in result["indicators"]}
        self.assertEqual(result["packets_read"], 4)
        self.assertEqual(result["flow_count"], 4)
        self.assertFalse(by_value["192.168.10.5"]["is_public"])
        self.assertTrue(by_value["8.8.8.8"]["is_public"])
        self.assertIn("dns_query", by_value["example.com"]["observed_in"])
        self.assertIn("http_host", by_value["example.com"]["observed_in"])
        self.assertIn("http://example.com/status", by_value)
        api_values = {item["value"] for item in result["api_ready_indicators"]}
        self.assertIn("8.8.8.8", api_values)
        self.assertNotIn("192.168.10.5", api_values)
        self.assertNotIn("239.255.255.250", api_values)
        self.assertNotIn("1.10.168.192.in-addr.arpa", api_values)

    def test_packet_limit_marks_result_truncated(self) -> None:
        packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2)
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "limited.pcap"
            wrpcap(str(capture), [packet, packet])
            result = extract_pcap_indicators(capture, max_packets=1)

        self.assertEqual(result["packets_read"], 1)
        self.assertTrue(result["truncated"])


if __name__ == "__main__":
    unittest.main()
