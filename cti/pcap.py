"""PCAP-to-CTI extraction for attributable network indicators.

The CatBoost detector consumes precomputed numeric flow features.  PCAP files
serve a different purpose here: they preserve packet-level context from which
we can extract IP addresses, DNS names, and HTTP URLs that OTX and VirusTotal
can actually query.  The extractor deliberately keeps private indicators in
the audit output but marks them as local so they are never sent externally.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from cti.indicators import classify_indicator, is_public_indicator


def _decode(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _record_indicator(
    indicators: dict[tuple[str, str], dict[str, Any]],
    value: str,
    field: str,
    *,
    packet_number: int,
    flow_key: str | None,
) -> None:
    value = value.strip()
    if not value:
        return
    try:
        normalized, indicator_type = classify_indicator(value)
    except ValueError:
        return

    identity = (indicator_type, normalized)
    record = indicators.setdefault(
        identity,
        {
            "value": normalized,
            "indicator_type": indicator_type,
            "is_public": is_public_indicator(normalized, indicator_type),
            "observed_in": set(),
            "packet_numbers": [],
            "flow_keys": set(),
        },
    )
    record["observed_in"].add(field)
    if len(record["packet_numbers"]) < 10:
        record["packet_numbers"].append(packet_number)
    if flow_key:
        record["flow_keys"].add(flow_key)


def extract_pcap_indicators(
    pcap_path: str | Path,
    *,
    max_packets: int = 100_000,
    max_flows: int = 5_000,
) -> dict[str, Any]:
    """Stream a PCAP/PCAPNG file and return attributable indicators and flows.

    This function never performs a network request.  Its ``api_ready_indicators``
    output is the only list intended for OTX/VirusTotal enrichment.  NVD and OSV
    need CVE/package metadata from an asset inventory, which packet captures do
    not reliably provide.
    """

    try:
        from scapy.all import DNSQR, IP, IPv6, TCP, UDP, PcapReader
        from scapy.layers.http import HTTPRequest
    except ImportError as exc:  # pragma: no cover - exercised in deployment only
        raise RuntimeError(
            "PCAP extraction requires Scapy. Install dependencies with "
            "`python -m pip install -r requirements.txt`."
        ) from exc

    source = Path(pcap_path).expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(f"PCAP file not found: {source}")
    if max_packets <= 0 or max_flows <= 0:
        raise ValueError("max_packets and max_flows must be positive integers.")

    indicators: dict[tuple[str, str], dict[str, Any]] = {}
    flows: dict[str, dict[str, Any]] = {}
    protocols: Counter[str] = Counter()
    packets_read = 0
    bytes_read = 0
    truncated = False

    reader = PcapReader(str(source))
    try:
        for packet_number, packet in enumerate(reader, start=1):
            if packet_number > max_packets:
                truncated = True
                break
            packets_read += 1
            bytes_read += len(packet)

            src_ip = dst_ip = None
            if IP in packet:
                src_ip, dst_ip = packet[IP].src, packet[IP].dst
            elif IPv6 in packet:
                src_ip, dst_ip = packet[IPv6].src, packet[IPv6].dst

            protocol = "other"
            source_port = destination_port = None
            if TCP in packet:
                protocol = "tcp"
                source_port, destination_port = int(packet[TCP].sport), int(packet[TCP].dport)
            elif UDP in packet:
                protocol = "udp"
                source_port, destination_port = int(packet[UDP].sport), int(packet[UDP].dport)
            elif src_ip and dst_ip:
                protocol = "ip"
            protocols[protocol] += 1

            flow_key = None
            if src_ip and dst_ip:
                flow_key = f"{src_ip}:{source_port or 0}>{dst_ip}:{destination_port or 0}/{protocol}"
                if flow_key in flows or len(flows) < max_flows:
                    flow = flows.setdefault(
                        flow_key,
                        {
                            "flow_key": flow_key,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": source_port,
                            "dst_port": destination_port,
                            "protocol": protocol,
                            "packet_count": 0,
                            "byte_count": 0,
                            "first_packet": packet_number,
                            "last_packet": packet_number,
                        },
                    )
                    flow["packet_count"] += 1
                    flow["byte_count"] += len(packet)
                    flow["last_packet"] = packet_number

                _record_indicator(
                    indicators,
                    src_ip,
                    "src_ip",
                    packet_number=packet_number,
                    flow_key=flow_key,
                )
                _record_indicator(
                    indicators,
                    dst_ip,
                    "dst_ip",
                    packet_number=packet_number,
                    flow_key=flow_key,
                )

            if DNSQR in packet:
                query_name = _decode(packet[DNSQR].qname).rstrip(".")
                _record_indicator(
                    indicators,
                    query_name,
                    "dns_query",
                    packet_number=packet_number,
                    flow_key=flow_key,
                )

            if HTTPRequest in packet:
                request = packet[HTTPRequest]
                host = _decode(getattr(request, "Host", b"")).strip()
                path = _decode(getattr(request, "Path", b"/")).strip() or "/"
                _record_indicator(
                    indicators,
                    host,
                    "http_host",
                    packet_number=packet_number,
                    flow_key=flow_key,
                )
                if host:
                    _record_indicator(
                        indicators,
                        f"http://{host}{path}",
                        "http_url",
                        packet_number=packet_number,
                        flow_key=flow_key,
                    )
    finally:
        reader.close()

    serialized_indicators = []
    for record in indicators.values():
        serialized_indicators.append(
            {
                **record,
                "observed_in": sorted(record["observed_in"]),
                "flow_keys": sorted(record["flow_keys"]),
            }
        )
    serialized_indicators.sort(key=lambda item: (item["indicator_type"], item["value"]))

    api_ready = [
        item
        for item in serialized_indicators
        if item["is_public"]
        and item["indicator_type"] in {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"}
    ]

    return {
        "pcap_file": str(source),
        "packets_read": packets_read,
        "bytes_read": bytes_read,
        "truncated": truncated,
        "protocol_counts": dict(sorted(protocols.items())),
        "flow_count": len(flows),
        "flows": list(flows.values()),
        "indicators": serialized_indicators,
        "api_ready_indicators": api_ready,
        "routing": {
            "otx_virustotal": "Public IP, domain, URL, and file-hash indicators extracted from this capture.",
            "nvd_osv": "Requires attributable CVE or package/version metadata from the monitored asset inventory; not inferred from numeric flow features.",
        },
    }
