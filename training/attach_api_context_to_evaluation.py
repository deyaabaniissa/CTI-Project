"""Attach auditable CTI query context to the 300 held-out TEST samples.

The numeric CICIoMT2024 TEST export does not include observables.  This script
does not invent them.  It attaches two real, separately sourced context planes:

* a public network indicator extracted from the official PCAP catalog; and
* an exact dependency version read from this deployed project's lock files.

The resulting fields let OTX/VirusTotal and OSV/NVD return useful live details
while retaining an explicit ``attributable_to_numeric_test_row = False`` marker.
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
from pathlib import Path
from typing import Any


PACKAGE_NAMES = ("flask", "dompurify", "nanoid", "postcss")


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--artifact",
        type=Path,
        default=root / "data/evaluation/official_test_50_samples_per_family_full_results.json",
    )
    parser.add_argument(
        "--indicators",
        type=Path,
        default=root / "pcap_api_ready_indicators.csv",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=root / "data/evaluation/official_test_300_api_context.csv",
    )
    parser.add_argument("--project-root", type=Path, default=root)
    return parser.parse_args()


def _parsed_list(value: Any) -> list[Any]:
    try:
        parsed = ast.literal_eval(str(value or "[]"))
    except (SyntaxError, ValueError):
        return []
    return list(parsed) if isinstance(parsed, (list, tuple, set)) else []


def load_network_indicators(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        for item in csv.DictReader(source):
            value = str(item.get("value") or "").strip()
            indicator_type = str(item.get("indicator_type") or "").strip().lower()
            is_public = str(item.get("is_public") or "").strip().lower() in {
                "1", "true", "yes"
            }
            if not value or not is_public or indicator_type not in {
                "domain", "url", "ipv4", "ipv6", "md5", "sha1", "sha256"
            }:
                continue
            rows.append(
                {
                    "indicator": value,
                    "indicator_type": indicator_type,
                    "source_file": path.name,
                    "observed_in": _parsed_list(item.get("observed_in")),
                    "packet_numbers": _parsed_list(item.get("packet_numbers")),
                    "flow_keys": _parsed_list(item.get("flow_keys")),
                }
            )
    if not rows:
        raise ValueError(f"No public API-ready network indicators found in {path}")
    return rows


def load_packages(root: Path) -> list[dict[str, str]]:
    discovered: dict[str, dict[str, str]] = {}
    requirements = root / "requirements.txt"
    for raw_line in requirements.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if "==" not in line:
            continue
        name, version = (part.strip() for part in line.split("==", 1))
        canonical = name.lower().replace("_", "-")
        if canonical in PACKAGE_NAMES and version:
            discovered[canonical] = {
                "identifier": f"PyPI:{name}:{version}",
                "ecosystem": "PyPI",
                "name": name,
                "version": version,
                "source_file": "requirements.txt",
            }

    package_lock = root / "cti-dashboard/package-lock.json"
    lock_payload = json.loads(package_lock.read_text(encoding="utf-8"))
    for package_path, package in (lock_payload.get("packages") or {}).items():
        if not isinstance(package, dict):
            continue
        name = str(package.get("name") or "").strip()
        if not name and "node_modules/" in str(package_path):
            name = str(package_path).rsplit("node_modules/", 1)[-1].strip()
        version = str(package.get("version") or "").strip()
        canonical = name.lower().replace("_", "-")
        if canonical in PACKAGE_NAMES and version:
            discovered[canonical] = {
                "identifier": f"npm:{name}:{version}",
                "ecosystem": "npm",
                "name": name,
                "version": version,
                "source_file": "cti-dashboard/package-lock.json",
            }

    packages = [discovered[name] for name in PACKAGE_NAMES if name in discovered]
    if not packages:
        raise ValueError("No exact package versions were found in the project lock files")
    return packages


def main() -> int:
    args = parse_args()
    payload = json.loads(args.artifact.read_text(encoding="utf-8"))
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list) or len(results) != 300:
        raise ValueError("Expected exactly 300 evaluation results")

    indicators = load_network_indicators(args.indicators)
    packages = load_packages(args.project_root)
    manifest_rows: list[dict[str, Any]] = []

    for index, item in enumerate(results):
        event = item.get("event") if isinstance(item, dict) else None
        if not isinstance(event, dict):
            raise ValueError(f"Result {index} has no event")
        network = indicators[index % len(indicators)]
        package = packages[index % len(packages)]
        true_family = str(event["ground_truth_family"])
        sample_number = int(event["sample_number_in_family"])
        sample_id = f"CIC24-TEST-{true_family.upper()}-{sample_number:03d}"
        context = {
            "network": network,
            "dependency": package,
            "nvd_query_mode": "CVE aliases returned live by OSV for the exact package version",
            "evidence_scope": "project_capture_and_dependency_context",
            "attributable_to_numeric_test_row": False,
            "assignment_method": (
                "deterministic rotation of real project indicators for repeatable CTI demonstration"
            ),
        }
        event["api_context"] = context
        manifest_rows.append(
            {
                "sample_id": sample_id,
                "true_family": true_family,
                "sample_position": int(event["sample_position"]),
                "network_indicator": network["indicator"],
                "network_indicator_type": network["indicator_type"],
                "network_source_file": network["source_file"],
                "package_identifier": package["identifier"],
                "package_ecosystem": package["ecosystem"],
                "package_name": package["name"],
                "package_version": package["version"],
                "package_source_file": package["source_file"],
                "nvd_query_mode": context["nvd_query_mode"],
                "evidence_scope": context["evidence_scope"],
                "attributable_to_numeric_test_row": False,
            }
        )

    payload["notice"] = (
        "300 unique CICIoMT2024 Official TEST rows evaluated by CatBoost. Each row also "
        "carries an explicitly non-attributable CTI demonstration context sourced from "
        "the official PCAP indicator catalog and the deployed project's dependency files."
    )
    args.artifact.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    with args.manifest.open("w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=list(manifest_rows[0]))
        writer.writeheader()
        writer.writerows(manifest_rows)

    print(f"Updated evaluation artifact: {args.artifact}")
    print(f"Saved 300-row API context manifest: {args.manifest}")
    print(f"Network indicators rotated: {len(indicators)}")
    print(f"Exact package versions rotated: {len(packages)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
