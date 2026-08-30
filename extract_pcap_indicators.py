"""Extract CTI-ready indicators from one PCAP/PCAPNG capture."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cti.pcap import extract_pcap_indicators


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Extract per-capture/per-flow IP, DNS, and HTTP indicators. "
            "The command does not contact external APIs."
        )
    )
    parser.add_argument("pcap", type=Path, help="Path to a .pcap, .pcapng, or .cap file")
    parser.add_argument(
        "--output",
        type=Path,
        help="JSON output path (default: <pcap-name>_indicators.json)",
    )
    parser.add_argument("--max-packets", type=int, default=100_000)
    parser.add_argument("--max-flows", type=int, default=5_000)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = extract_pcap_indicators(
        args.pcap,
        max_packets=args.max_packets,
        max_flows=args.max_flows,
    )
    output = args.output or args.pcap.with_name(f"{args.pcap.stem}_indicators.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Packets: {result['packets_read']:,}")
    print(f"Flows: {result['flow_count']:,}")
    print(f"All indicators: {len(result['indicators']):,}")
    print(f"Public CTI-ready indicators: {len(result['api_ready_indicators']):,}")
    print(f"Saved: {output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
