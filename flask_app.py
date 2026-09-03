from __future__ import annotations

import asyncio
import ast
import csv
import hashlib
import hmac
import json
import os
import random
import secrets
import tempfile
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory, session
from flask_sock import Sock
from werkzeug.utils import secure_filename

from cti.catboost_ids import CatBoostIDSService
from cti.db.site_persistence import SitePersistenceService
from cti.extraction import extract_indicators
from cti.intelligence import ThreatIntelligenceService
from cti.pcap import extract_pcap_indicators
from cti.pcap_features import compute_flow_features
from cti.reporting import summarize_provider_evidence


PROJECT_ROOT = Path(__file__).resolve().parent
DIST_DIR = PROJECT_ROOT / "cti-dashboard" / "dist"
MODEL_PATH = PROJECT_ROOT / "model" / "ciciomt2024_catboost_12_features_6_classes.joblib"
SAMPLE_PATH = PROJECT_ROOT / "data" / "demo" / "integration_sample.json"
OFFICIAL_TEST_REPLAY_PATH = (
    PROJECT_ROOT
    / "data"
    / "evaluation"
    / "official_test_50_samples_per_family_full_results.json"
)
SPOOFING_PCAP_EVIDENCE_PATH = PROJECT_ROOT / "pcap_attributable_evidence.json"
PCAP_API_READY_INDICATORS_PATH = PROJECT_ROOT / "pcap_api_ready_indicators.csv"
PROJECT_SECURITY_PACKAGE_NAMES = ("flask", "dompurify", "nanoid", "postcss")
RESULTS_PATH = PROJECT_ROOT / "outputs" / "flask_investigations.jsonl"
PCAP_RESULT_PATH = PROJECT_ROOT / "outputs" / "pcap_investigations.jsonl"

PCAP_SAMPLE_FILES = {
    "benign": PROJECT_ROOT / "CIC dataset" / "WiFi_and_MQTT" / "attacks" / "PCAP" / "test" / "Benign_test.pcap",
    "ddos": PROJECT_ROOT / "CIC dataset" / "WiFi_and_MQTT" / "attacks" / "PCAP" / "test" / "TCP_IP-DDoS-ICMP1_test.pcap",
    "dos": PROJECT_ROOT / "CIC dataset" / "WiFi_and_MQTT" / "attacks" / "PCAP" / "test" / "MQTT-DoS-Connect_Flood_test.pcap",
    "mqtt": PROJECT_ROOT / "CIC dataset" / "WiFi_and_MQTT" / "attacks" / "PCAP" / "test" / "MQTT-Malformed_Data_test.pcap",
    "recon": PROJECT_ROOT / "CIC dataset" / "WiFi_and_MQTT" / "attacks" / "PCAP" / "test" / "Recon-Ping_Sweep_test.pcap",
    "spoofing": PROJECT_ROOT / "CIC dataset" / "WiFi_and_MQTT" / "attacks" / "PCAP" / "test" / "ARP_Spoofing_test.pcap",
}

load_dotenv(PROJECT_ROOT / ".env")
RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class AsyncRunner:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()

    def run(self, coroutine: Any, timeout: float = 90.0) -> Any:
        future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        return future.result(timeout=timeout)


runner = AsyncRunner()
model_service = CatBoostIDSService(MODEL_PATH)
intelligence = ThreatIntelligenceService(PROJECT_ROOT)
recent_alerts: deque[dict[str, Any]] = deque(maxlen=100)
database = SitePersistenceService(model_service.metadata, str(MODEL_PATH))
database_startup = database.initialize()


def load_integration_sample() -> dict[str, Any]:
    payload = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    event = payload.get("event") if isinstance(payload, dict) else None
    if not isinstance(event, dict):
        raise ValueError("Integration JSON does not contain an event object.")
    return event


def flatten_event(payload: Mapping[str, Any]) -> dict[str, Any]:
    event: dict[str, Any] = {}
    for section in ("features", "iocs", "asset"):
        value = payload.get(section)
        if isinstance(value, Mapping):
            event.update(value)
    event.update({key: value for key, value in payload.items() if key not in {"features", "iocs", "asset"}})
    aliases = {
        "src_ip": "source_ip",
        "dst_ip": "destination_ip",
        "hash": "file_hash",
        "cve": "cve_id",
    }
    for source, target in aliases.items():
        if event.get(source) and not event.get(target):
            event[target] = event[source]
    return event


VALID_TLP = {"TLP:RED", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR"}


def normalize_tlp(value: Any, *, default: str) -> str:
    normalized = str(value or default).strip().upper()
    return normalized if normalized in VALID_TLP else default


def attack_probability(prediction: Mapping[str, Any]) -> float:
    """Return P(any attack), distinct from confidence in the winning class."""

    probabilities = prediction.get("probabilities") or {}
    benign_probability = float(probabilities.get("Benign", 0.0) or 0.0)
    return min(max(1.0 - benign_probability, 0.0), 1.0)


def live_fused_risk(
    log: Mapping[str, Any],
    evidence: list[Mapping[str, Any]],
) -> dict[str, Any]:
    """Fuse only API evidence attributable to the exact live event.

    CatBoost P(non-Benign) remains an immutable model output. Capture-wide and
    dependency-context findings are excluded so they cannot change a held-out
    TEST row's score.
    """

    model_attack_score = min(
        max(float(log.get("attack_probability") or 0.0), 0.0),
        1.0,
    )
    attributable = [
        item
        for item in evidence
        if (item.get("provenance") or {}).get("attributable_to_log", True) is not False
    ]
    adverse = [
        item
        for item in attributable
        if str(item.get("verdict") or "").lower() in {"malicious", "vulnerable"}
    ]
    cti_score = max(
        (float(item.get("confidence") or 0.0) for item in adverse),
        default=0.0,
    )

    if not attributable:
        score = round(100.0 * model_attack_score, 2)
        level = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 40 else "low"
        boundary = (
            "Live CTI returned context-only evidence"
            if evidence
            else "No attributable indicator was available for live CTI enrichment"
        )
        return {
            "score": score,
            "level": level,
            "cti_score": 0.0,
            "applied": False,
            "reason": (
                f"{boundary}, so no CTI adjustment was applied. "
                f"CatBoost P(non-Benign) remains {model_attack_score:.2%}."
            ),
        }

    asset_criticality = min(
        max(float(log.get("asset_criticality") or 0.8), 0.0),
        1.0,
    )
    score = round(
        100.0 * (
            0.60 * model_attack_score
            + 0.25 * cti_score
            + 0.15 * asset_criticality
        ),
        2,
    )
    level = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 40 else "low"
    return {
        "score": score,
        "level": level,
        "cti_score": round(cti_score, 6),
        "applied": True,
        "reason": (
            f"Live fused risk: {score:.2f}% ({level}), using CatBoost P(non-Benign) "
            f"{model_attack_score:.2%} and attributable live CTI score {cti_score:.2%}."
        ),
    }


@lru_cache(maxsize=1)
def load_official_test_replay() -> tuple[dict[str, Any], ...]:
    if not OFFICIAL_TEST_REPLAY_PATH.is_file():
        raise FileNotFoundError(
            "The 300-row CICIoMT2024 Official TEST result artifact is missing."
        )

    payload = json.loads(OFFICIAL_TEST_REPLAY_PATH.read_text(encoding="utf-8"))
    raw_results = payload.get("results") if isinstance(payload, Mapping) else None
    if not isinstance(raw_results, list) or len(raw_results) != 300:
        raise ValueError("Expected exactly 300 official evaluation results.")

    rows: list[dict[str, Any]] = []
    for item in raw_results:
        event = item.get("event") if isinstance(item, Mapping) else None
        result = item.get("result") if isinstance(item, Mapping) else None
        prediction = result.get("prediction") if isinstance(result, Mapping) else None
        if not isinstance(event, Mapping) or not isinstance(result, Mapping) or not isinstance(prediction, Mapping):
            raise ValueError("An official evaluation result is missing event or prediction data.")

        true_family = str(event["ground_truth_family"])
        predicted_family = str(prediction["predicted_family"])
        sample_number = int(event["sample_number_in_family"])
        features = {feature: float(event[feature]) for feature in model_service.features}
        probabilities = {
            family: float((prediction.get("probabilities") or {}).get(family, 0.0))
            for family in model_service.classes
        }
        api_context = event.get("api_context")
        if api_context is not None and not isinstance(api_context, Mapping):
            raise ValueError("An official evaluation result has invalid API context data.")
        # The official CICIoMT2024 TEST rows contain flow features only.  The
        # optional api_context is a separately sourced, explicitly
        # non-attributable demonstration plane.  It makes all four live clients
        # testable without pretending that an IoC or dependency was a native
        # column of this exact numeric row.
        evaluation_event = {
            **features,
            "ground_truth_family": true_family,
            "sample_number_in_family": sample_number,
            "sample_position": int(event["sample_position"]),
            "sample_origin": str(event.get("sample_origin") or "CICIoMT2024 Official TEST"),
        }
        if api_context:
            evaluation_event["api_context"] = dict(api_context)
        model_attack_score = attack_probability(prediction)
        risk_score = round(100.0 * model_attack_score, 2)
        risk_level = (
            "critical" if risk_score >= 80
            else "high" if risk_score >= 60
            else "medium" if risk_score >= 40
            else "low"
        )
        rows.append({
            "sample_id": f"CIC24-TEST-{true_family.upper()}-{sample_number:03d}",
            "source_dataset": "CICIoMT2024",
            "source_split": "Official TEST",
            "source_file": "CICIoMT2024 Official TEST evaluation",
            "source_row_number": int(event["sample_position"]),
            "attack_subclass": true_family,
            "true_family": true_family,
            "predicted_family": predicted_family,
            "confidence": float(prediction["confidence"]),
            "correct": predicted_family == true_family,
            "probabilities": probabilities,
            "features": features,
            "event": evaluation_event,
            "api_context": dict(api_context) if api_context else None,
            "cti_summary": [],
            "observables": {},
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommended_action_texts": [],
            "source_investigation_id": str(result.get("investigation_id") or ""),
            "source_created_at": str(result.get("created_at") or ""),
        })
    correct = sum(int(bool(row["correct"])) for row in rows)
    evaluation_metadata = model_service.metadata.setdefault("evaluation", {})
    evaluation_metadata.update({
        "website_replay_rows": len(rows),
        "website_replay_rows_per_family": 50,
        "website_replay_accuracy": correct / len(rows),
    })
    return tuple(rows)


def evaluation_recommendations(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    predicted_family = str(row.get("predicted_family") or "Benign")
    true_family = str(row.get("true_family") or "Unknown")
    correct = bool(row.get("correct"))
    confidence = float(row.get("confidence") or 0.0)

    if not correct and true_family == "Benign":
        primary_action = {
            "priority": "Review",
            "action": (
                "Review this false-positive prediction against the Benign and "
                f"{predicted_family} feature distributions. Do not initiate containment "
                "from this held-out evaluation row."
            ),
            "problem": (
                f"The official TEST label is Benign, but CatBoost predicted {predicted_family}."
            ),
            "evidence_sources": ["CICIoMT2024 Official TEST", "CICIoMT2024 CatBoost"],
            "evidence": (
                f"Ground truth Benign; predicted {predicted_family}; "
                f"predicted-class confidence {confidence:.2%}. Contextual CTI is not attributable "
                "to this numeric TEST row."
            ),
        }
    elif not correct and predicted_family == "Benign":
        primary_action = {
            "priority": "Review",
            "action": (
                "Review this false-negative miss, inspect the class threshold and feature values, "
                "and add the row to model error analysis. This TEST row is not a live incident."
            ),
            "problem": f"The official TEST label is {true_family}, but CatBoost predicted Benign.",
            "evidence_sources": ["CICIoMT2024 Official TEST", "CICIoMT2024 CatBoost"],
            "evidence": (
                f"Ground truth {true_family}; predicted Benign; predicted-class confidence "
                f"{confidence:.2%}."
            ),
        }
    elif not correct:
        primary_action = {
            "priority": "Review",
            "action": (
                f"Review the class confusion between {true_family} and {predicted_family}. "
                "Do not execute incident-response containment from a held-out TEST row."
            ),
            "problem": (
                f"The official TEST label is {true_family}, but CatBoost predicted "
                f"{predicted_family}."
            ),
            "evidence_sources": ["CICIoMT2024 Official TEST", "CICIoMT2024 CatBoost"],
            "evidence": f"Incorrect family prediction with {confidence:.2%} predicted-class confidence.",
        }
    elif true_family == "Benign":
        primary_action = {
            "priority": "Validation",
            "action": (
                "Record this correctly classified Benign row as validation evidence. "
                "No incident-response containment is recommended."
            ),
            "problem": "No model error was observed for this held-out Benign row.",
            "evidence_sources": ["CICIoMT2024 Official TEST", "CICIoMT2024 CatBoost"],
            "evidence": f"Correct Benign prediction with {confidence:.2%} confidence.",
        }
    else:
        primary_action = {
            "priority": "Validation",
            "action": (
                f"Record this correctly classified {true_family} row as model-validation evidence. "
                "Operational containment requires a separate live event with attributable indicators."
            ),
            "problem": f"CatBoost correctly classified the held-out row as {true_family}.",
            "evidence_sources": ["CICIoMT2024 Official TEST", "CICIoMT2024 CatBoost"],
            "evidence": f"Correct {true_family} prediction with {confidence:.2%} confidence.",
        }

    actions = [primary_action]
    family_playbooks = {
        "DDoS": (
            "If a live event reproduces this DDoS pattern, enable upstream DDoS mitigation, "
            "apply protocol-aware rate limits, preserve source/flow indicators, and coordinate "
            "with the ISP or scrubbing provider before blocking broad address ranges.",
            "A distributed flood can exhaust bandwidth, connection tables, or the targeted IoMT service.",
        ),
        "DoS": (
            "If a live event reproduces this DoS pattern, isolate the affected service, apply "
            "per-source connection and request limits, capture the source IP and five-tuple, "
            "and verify recovery after the traffic is contained.",
            "A concentrated denial-of-service flow can exhaust one device or service endpoint.",
        ),
        "MQTT": (
            "If confirmed on live MQTT traffic, restrict broker access with ACLs, require TLS, "
            "rotate exposed credentials, cap client connection/publish rates, and preserve the "
            "client ID and broker address for investigation.",
            "Abusive or malformed MQTT traffic can disrupt broker availability and IoMT messaging.",
        ),
        "Recon": (
            "If confirmed in live traffic, identify and preserve the scanning source, restrict "
            "unnecessary ports at the segment boundary, review the targeted services, and "
            "increase monitoring for follow-on exploitation attempts.",
            "Reconnaissance can reveal reachable services and precede exploitation.",
        ),
        "Spoofing": (
            "If confirmed in live traffic, validate the IP-to-MAC mapping, isolate the suspect "
            "switch port, enable DHCP snooping and Dynamic ARP Inspection where supported, "
            "and renew trusted ARP entries after containment.",
            "ARP or identity spoofing can redirect traffic and enable interception or impersonation.",
        ),
    }
    if correct and true_family in family_playbooks:
        action, problem = family_playbooks[true_family]
        actions.append(
            {
                "priority": "If confirmed live",
                "action": action,
                "problem": problem,
                "evidence_sources": ["CICIoMT2024 CatBoost", "Local incident-response playbook"],
                "evidence": (
                    f"The held-out row was correctly classified as {true_family} with "
                    f"{confidence:.2%} predicted-class confidence. This is conditional guidance, "
                    "not proof that a live incident occurred."
                ),
            }
        )
    actions.append(
        {
            "priority": "Review",
            "action": "Preserve the original feature row and prediction for analyst review.",
            "problem": "Maintain evaluation evidence and traceability.",
            "evidence_sources": ["CICIoMT2024 Official TEST"],
            "evidence": "No threat-intelligence indicator is present in this flow row.",
        }
    )
    return actions


def evaluation_provider_evidence(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    source_states = intelligence.status()["sources"]
    evidence = summarize_provider_evidence([], source_states)
    has_context = isinstance(row.get("api_context"), Mapping)
    provider_requirements = {
        "otx": "the attached public IP/domain/hash from the official PCAP catalog",
        "virustotal": "the attached public IP/domain/hash from the official PCAP catalog",
        "osv": "the attached exact package name and version from the project dependency files",
        "nvd": "the real CVE aliases returned by OSV for that exact package version",
    }
    for provider in evidence:
        state = source_states.get(provider["provider_id"]) or {}
        provider["connection_status"] = str(state.get("status") or "unknown")
        provider["connection_verified_at"] = state.get("last_success")
        provider["connection_error"] = state.get("last_error")
        if has_context:
            provider["applicable"] = True
            provider["status"] = "not_queried" if state.get("configured") else "not_configured"
            provider["result"] = (
                f"Ready for a fresh lookup using {provider_requirements[provider['provider_id']]}. "
                "Open the report and select Verify API connectivity to query this source live. "
                "The result is project context and is not treated as a native field of the "
                "numeric TEST row."
            )
            continue
        if state.get("status") == "live":
            provider["result"] = (
                f"Live API connection verified at {state.get('last_success') or 'the latest check'}. "
                "No compatible row-specific indicator was sent, so no provider finding is "
                "claimed as evidence for this exact numeric TEST row."
            )
        else:
            provider["result"] = (
                "No compatible row-specific indicator was available, and the latest API "
                f"connection state is {state.get('status') or 'unknown'}."
            )
    return evidence


async def enrich_evaluation_api_context(
    row: Mapping[str, Any],
    *,
    force_refresh: bool,
) -> list[dict[str, Any]]:
    """Query the two real context planes attached to one evaluation sample.

    Network observables come from the official PCAP indicator catalog and are
    sent to OTX/VirusTotal.  Package coordinates come from the deployed
    project's lock files and are sent to OSV; CVE aliases returned by OSV are
    then sent to NVD.  Both remain non-attributable to the numeric TEST row.
    """

    context = row.get("api_context")
    if not isinstance(context, Mapping):
        return []
    network = context.get("network")
    dependency = context.get("dependency")
    jobs: list[tuple[Mapping[str, Any], Any]] = []
    if isinstance(network, Mapping) and str(network.get("indicator") or "").strip():
        jobs.append(
            (
                network,
                intelligence.enrich_indicator(
                    str(network["indicator"]),
                    force_refresh=force_refresh,
                ),
            )
        )
    if isinstance(dependency, Mapping) and str(dependency.get("identifier") or "").strip():
        jobs.append(
            (
                dependency,
                intelligence.enrich_package(
                    str(dependency["identifier"]),
                    force_refresh=force_refresh,
                ),
            )
        )
    if not jobs:
        return []

    results = await asyncio.gather(
        *(job for _, job in jobs),
        return_exceptions=True,
    )
    evidence: list[dict[str, Any]] = []
    for (source, _), result in zip(jobs, results):
        is_dependency = "identifier" in source
        provenance = {
            "evidence_scope": (
                "deployed_platform_dependency"
                if is_dependency
                else "official_pcap_capture"
            ),
            "attributable_to_log": False,
            "source_file": source.get("source_file"),
            "assignment_method": context.get("assignment_method"),
        }
        indicator = str(
            source.get("identifier") if is_dependency else source.get("indicator")
        )
        indicator_type = "package" if is_dependency else str(source.get("indicator_type"))
        applicable_sources = ["osv", "nvd"] if is_dependency else ["otx", "virustotal"]
        if isinstance(result, Exception):
            evidence.append(
                {
                    "indicator": indicator,
                    "type": indicator_type,
                    "field": "project dependency context" if is_dependency else "official PCAP context",
                    "verdict": "unknown",
                    "confidence": 0.0,
                    "sources": {},
                    "coverage": {
                        "applicable_sources": applicable_sources,
                        "configured_sources": [],
                        "available_sources": [],
                        "queried_sources": [],
                        "complete": False,
                    },
                    "message": str(result)[:240],
                    "provenance": provenance,
                }
            )
        else:
            evidence.append(
                {
                    **result,
                    "field": "project dependency context" if is_dependency else "official PCAP context",
                    "provenance": provenance,
                }
            )
    return evidence


@lru_cache(maxsize=1)
def load_spoofing_capture_indicators() -> tuple[dict[str, Any], ...]:
    """Load public IoCs attributable to the official ARP Spoofing capture.

    These are capture-level context, not per-row fields.  The report labels
    that distinction explicitly and never assigns them to other families.
    """

    if not SPOOFING_PCAP_EVIDENCE_PATH.is_file():
        return ()
    payload = json.loads(SPOOFING_PCAP_EVIDENCE_PATH.read_text(encoding="utf-8"))
    rows = payload.get("api_ready_indicators") if isinstance(payload, Mapping) else None
    if not isinstance(rows, list):
        return ()
    valid = [
        {
            "value": str(row.get("value") or ""),
            "indicator_type": str(row.get("indicator_type") or ""),
            "observed_in": list(row.get("observed_in") or []),
            "packet_numbers": list(row.get("packet_numbers") or []),
            "flow_keys": list(row.get("flow_keys") or []),
        }
        for row in rows
        if isinstance(row, Mapping) and str(row.get("value") or "").strip()
    ]
    return tuple(valid)


async def enrich_spoofing_capture_context(
    sample_number: int,
    *,
    force_refresh: bool,
) -> list[dict[str, Any]]:
    indicators = load_spoofing_capture_indicators()
    if not indicators:
        return []

    domains = [row for row in indicators if row["indicator_type"] == "domain"]
    addresses = [row for row in indicators if row["indicator_type"] in {"ipv4", "ipv6"}]
    selected: list[dict[str, Any]] = []
    if domains:
        selected.append(domains[(sample_number - 1) % len(domains)])
    if addresses:
        selected.append(addresses[(sample_number - 1) % len(addresses)])

    results = await asyncio.gather(
        *(
            intelligence.enrich_indicator(row["value"], force_refresh=force_refresh)
            for row in selected
        ),
        return_exceptions=True,
    )
    evidence: list[dict[str, Any]] = []
    for row, result in zip(selected, results):
        if isinstance(result, Exception):
            evidence.append({
                "indicator": row["value"],
                "type": row["indicator_type"],
                "field": "ARP_Spoofing_test.pcap capture context",
                "verdict": "unknown",
                "confidence": 0.0,
                "sources": {},
                "coverage": {
                    "applicable_sources": ["otx", "virustotal"],
                    "configured_sources": [],
                    "available_sources": [],
                    "queried_sources": [],
                    "complete": False,
                },
                "message": str(result)[:240],
                "provenance": row,
            })
        else:
            evidence.append({
                **result,
                "field": "ARP_Spoofing_test.pcap capture context",
                "provenance": row,
            })
    return evidence


@lru_cache(maxsize=8)
def load_family_capture_indicators(family: str) -> tuple[dict[str, Any], ...]:
    """Load the API-ready indicator catalog exported from the official PCAP.

    The CSV is the requested bridge between numeric CICIoMT2024 model rows and
    CTI lookups. Indicators remain capture context; they are never described as
    native columns of one exact aggregated model row.
    """

    del family  # The supplied catalog currently represents one shared capture export.
    if not PCAP_API_READY_INDICATORS_PATH.is_file():
        return ()

    def parsed_list(value: Any) -> list[Any]:
        try:
            parsed = ast.literal_eval(str(value or "[]"))
        except (SyntaxError, ValueError):
            return []
        return list(parsed) if isinstance(parsed, (list, tuple, set)) else []

    rows: list[dict[str, Any]] = []
    with PCAP_API_READY_INDICATORS_PATH.open("r", encoding="utf-8-sig", newline="") as source:
        for item in csv.DictReader(source):
            value = str(item.get("value") or "").strip()
            indicator_type = str(item.get("indicator_type") or "").strip().lower()
            is_public = str(item.get("is_public") or "").strip().lower() in {"1", "true", "yes"}
            if not value or not is_public:
                continue
            rows.append({
                "value": value,
                "indicator_type": indicator_type,
                "observed_in": parsed_list(item.get("observed_in")),
                "packet_numbers": parsed_list(item.get("packet_numbers")),
                "flow_keys": parsed_list(item.get("flow_keys")),
                "capture_file": PCAP_API_READY_INDICATORS_PATH.name,
                "attributable_to_log": False,
            })
    return tuple(rows)


@lru_cache(maxsize=1)
def load_project_security_packages() -> tuple[dict[str, Any], ...]:
    """Read exact package versions from the project's real dependency files.

    These packages form a separate platform/SBOM evidence plane.  They are not
    represented as native fields of a CICIoMT2024 numeric flow row.  The small
    candidate list contains packages for which the bundled OSV-Scanner found a
    current advisory; versions are still read dynamically from the source
    files so stale or removed dependencies are never fabricated.
    """

    discovered: dict[str, dict[str, Any]] = {}
    requirements_path = PROJECT_ROOT / "requirements.txt"
    if requirements_path.is_file():
        for raw_line in requirements_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if "==" not in line:
                continue
            name, version = (part.strip() for part in line.split("==", 1))
            canonical_name = name.lower().replace("_", "-")
            if canonical_name not in PROJECT_SECURITY_PACKAGE_NAMES or not version:
                continue
            discovered[canonical_name] = {
                "value": f"PyPI:{name}:{version}",
                "indicator_type": "package",
                "package_name": name,
                "package_version": version,
                "ecosystem": "PyPI",
                "source_file": "requirements.txt",
                "evidence_scope": "deployed_platform_dependency",
                "attributable_to_log": False,
            }

    package_lock_path = PROJECT_ROOT / "cti-dashboard" / "package-lock.json"
    if package_lock_path.is_file():
        try:
            lock_payload = json.loads(package_lock_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            lock_payload = {}
        for package_path, package in (lock_payload.get("packages") or {}).items():
            if not isinstance(package, Mapping):
                continue
            name = str(package.get("name") or "").strip()
            if not name and "node_modules/" in str(package_path):
                name = str(package_path).rsplit("node_modules/", 1)[-1].strip()
            version = str(package.get("version") or "").strip()
            canonical_name = name.lower().replace("_", "-")
            if canonical_name not in PROJECT_SECURITY_PACKAGE_NAMES or not version:
                continue
            discovered[canonical_name] = {
                "value": f"npm:{name}:{version}",
                "indicator_type": "package",
                "package_name": name,
                "package_version": version,
                "ecosystem": "npm",
                "source_file": "cti-dashboard/package-lock.json",
                "evidence_scope": "deployed_platform_dependency",
                "attributable_to_log": False,
            }

    return tuple(
        discovered[name]
        for name in PROJECT_SECURITY_PACKAGE_NAMES
        if name in discovered
    )


async def enrich_family_capture_context(
    family: str,
    sample_number: int,
    *,
    force_refresh: bool,
) -> list[dict[str, Any]]:
    indicators = load_family_capture_indicators(family)
    if not indicators:
        return []

    domains = [row for row in indicators if row["indicator_type"] in {"domain", "url"}]
    addresses = [row for row in indicators if row["indicator_type"] in {"ipv4", "ipv6"}]
    hashes = [row for row in indicators if row["indicator_type"] in {"md5", "sha1", "sha256"}]
    vulnerabilities = [row for row in indicators if row["indicator_type"] in {"cve", "ghsa"}]
    packages = [row for row in indicators if row["indicator_type"] in {"package", "purl"}]
    project_packages = load_project_security_packages()
    selected: list[dict[str, Any]] = []
    for group in (domains, addresses, hashes, vulnerabilities, packages):
        if group:
            selected.append(group[(sample_number - 1) % len(group)])
    if project_packages:
        selected.append(project_packages[(sample_number - 1) % len(project_packages)])

    async def enrich_row(row: Mapping[str, Any]) -> dict[str, Any]:
        if row["indicator_type"] in {"package", "purl"}:
            return await intelligence.enrich_package(
                row["value"],
                force_refresh=force_refresh,
            )
        return await intelligence.enrich_indicator(
            row["value"],
            force_refresh=force_refresh,
        )

    results = await asyncio.gather(
        *(enrich_row(row) for row in selected),
        return_exceptions=True,
    )
    evidence: list[dict[str, Any]] = []
    capture_name = PCAP_API_READY_INDICATORS_PATH.name
    for row, result in zip(selected, results):
        is_package = row["indicator_type"] in {"package", "purl"}
        provenance = dict(row)
        # Capture-wide IoCs and deployed dependency findings are real project
        # evidence, but neither is a native field of this numeric TEST row.
        # Preserve that boundary so the report cannot label a Benign row as
        # malicious merely because the wider capture or platform has a finding.
        provenance["attributable_to_log"] = False
        if is_package:
            provenance.setdefault("source_file", "project dependency inventory")
            provenance.setdefault("evidence_scope", "deployed_platform_dependency")
            field = "deployed platform dependency inventory"
            applicable_sources = ["osv", "nvd"]
        else:
            provenance["capture_file"] = row.get("capture_file") or capture_name
            provenance.setdefault("evidence_scope", "official_pcap_capture")
            field = "pcap_api_ready_indicators.csv capture context"
            applicable_sources = ["otx", "virustotal"]
        if isinstance(result, Exception):
            evidence.append({
                "indicator": row["value"],
                "type": row["indicator_type"],
                "field": field,
                "verdict": "unknown",
                "confidence": 0.0,
                "sources": {},
                "coverage": {
                    "applicable_sources": applicable_sources,
                    "configured_sources": [],
                    "available_sources": [],
                    "queried_sources": [],
                    "complete": False,
                },
                "message": str(result)[:240],
                "provenance": provenance,
            })
        else:
            evidence.append({
                **result,
                "field": field,
                "provenance": provenance,
            })
    return evidence


def evaluation_dashboard_log(row: Mapping[str, Any]) -> dict[str, Any]:
    predicted_family = str(row["predicted_family"])
    confidence = float(row["confidence"])
    event = row.get("event") or {}
    cti_summary = row.get("cti_summary") or []
    risk_score = float(row.get("risk_score") or 0.0)
    risk_level = str(row.get("risk_level") or "low")
    is_in_otx = any(str(item.get("source")) == "OTX" and float(item.get("score") or 0.0) > 0 for item in cti_summary)
    # CICIoMT2024 is public evaluation data.  TLP describes sharing policy,
    # not model risk, so it must not be derived from severity.
    tlp = "TLP:CLEAR"
    provider_evidence = evaluation_provider_evidence(row)
    indicator_evidence: list[dict[str, Any]] = []
    has_api_context = isinstance(row.get("api_context"), Mapping)
    evidence_mode = "pending_context" if has_api_context else "not_applicable"
    return {
        "log_id": row["sample_id"],
        "report_type": "held_out_model_evaluation",
        "report_type_label": "Held-out model evaluation",
        "investigation_id": row["sample_id"],
        "date": "Official TEST",
        "timestamp": "Replay",
        "category": "IoMT network flows",
        "traffic_class": predicted_family,
        "true_family": row["true_family"],
        "prediction_correct": bool(row["correct"]),
        "attack_subclass": row["attack_subclass"],
        "department": "CICIoMT2024 model evaluation",
        "source_ip": "Not supplied by CICIoMT2024 flow export",
        "destination_target": row["source_file"],
        "source_dataset": row["source_dataset"],
        "source_split": row["source_split"],
        "source_row_number": row["source_row_number"],
        "data_mb": 0.0,
        "data_unit": "KB",
        "is_threat": int(predicted_family != "Benign"),
        "is_in_otx": is_in_otx,
        "risk_level": risk_level,
        "severity": risk_level,
        "risk_probability": round(risk_score / 100.0, 6),
        "attack_probability": round(risk_score / 100.0, 6),
        "risk_score": round(risk_score, 2),
        "model_probability": round(confidence, 6),
        "predicted_class_confidence": round(confidence, 6),
        "intel_verdict": (
            "Live CTI context ready — not attributable to the numeric TEST row"
            if has_api_context
            else "CTI not applicable — this TEST row has no attributable indicator"
        ),
        "tlp": tlp,
        "sharing_classification": tlp,
        "evaluation_mode": True,
        "original_event_time": "Not available in the CICIoMT2024 flow export",
        "replay_time": None,
        "features": row["features"],
        "api_context": row.get("api_context"),
        "class_probabilities": row["probabilities"],
        "provider_evidence": provider_evidence,
        "indicator_evidence": indicator_evidence,
        "evidence_mode": evidence_mode,
        "live_evidence_checked_at": None,
        "live_evidence_endpoint": f"/api/evaluation-samples/{row['sample_id']}/live-evidence",
        "recommended_actions": evaluation_recommendations(row),
        "recommendation_method": (
            "Evaluation-only guidance: ground truth is known. Do not execute operational "
            "containment from this held-out TEST row or from contextual CTI alone."
        ),
        "risk_reasons": [
            f"Ground truth: {row['true_family']}.",
            f"CatBoost prediction: {predicted_family} ({confidence:.1%}).",
            "Correct prediction." if row["correct"] else "Incorrect prediction retained for transparent evaluation.",
            f"CatBoost attack probability P(non-Benign): {risk_score:.2f}% ({risk_level} model score).",
            f"Predicted-class confidence: {confidence:.2%}.",
            (
                "This report can query all four APIs using separately sourced PCAP and "
                "dependency context. Any returned findings are displayed as project context "
                "and do not change the CatBoost evaluation result for this numeric TEST row."
                if has_api_context
                else "Opening this report verifies live API connectivity only. Provider findings "
                "are not requested because this numeric TEST row contains no attributable "
                "IP, domain, hash, CVE, or package identifier."
            ),
            "This unique row belongs only to the held-out CICIoMT2024 Official TEST split.",
        ],
        "model_details": {
            "model": model_service.metadata["model_name"],
            "predicted_family": predicted_family,
            "confidence": confidence,
            "probabilities": row["probabilities"],
            "features": row["features"],
        },
    }


# Keep the dedicated evaluation table synchronized without polluting the live
# hospital_events, model_predictions, alerts, or CTI lookup tables.
evaluation_database_sync = database.sync_evaluation_samples(load_official_test_replay())


async def enrich_event(
    event: Mapping[str, Any], *, force_refresh: bool = False
) -> list[dict[str, Any]]:
    candidates = extract_indicators(event)
    public = [candidate for candidate in candidates if candidate.is_public]
    results = await asyncio.gather(
        *(
            intelligence.enrich_indicator(
                candidate.value, force_refresh=force_refresh
            )
            for candidate in public
        ),
        return_exceptions=True,
    )
    evidence: list[dict[str, Any]] = []
    for candidate, result in zip(public, results):
        if isinstance(result, Exception):
            evidence.append({
                "indicator": candidate.value,
                "type": candidate.indicator_type,
                "field": candidate.field,
                "verdict": "unknown",
                "confidence": 0.0,
                "sources": {},
                "coverage": {
                    "applicable_sources": (
                        ["osv", "nvd"]
                        if candidate.indicator_type in {"cve", "ghsa"}
                        else ["otx", "virustotal"]
                    ),
                    "configured_sources": [],
                    "available_sources": [],
                    "queried_sources": [],
                    "complete": False,
                },
                "message": str(result)[:240],
            })
        else:
            evidence.append({**result, "field": candidate.field})
    return evidence


def recommendations(
    event: Mapping[str, Any],
    prediction: Mapping[str, Any],
    provider_rows: list[dict[str, Any]],
    risk_score: float,
) -> list[dict[str, Any]]:
    family = str(prediction["predicted_family"])
    actions: list[dict[str, Any]] = []

    def add(priority: str, action: str, problem: str, sources: list[str]) -> None:
        if action not in {item["action"] for item in actions}:
            actions.append({
                "priority": priority,
                "action": action,
                "problem": problem,
                "evidence_sources": sources,
                "evidence": f"CatBoost={family}; risk={risk_score:.1f}/100.",
            })

    if risk_score >= 80:
        add("Immediate", "Isolate the affected hospital endpoint or VLAN and begin incident triage.", "Critical combined risk.", ["CatBoost", "CTI fusion"])

    adverse_ioc_sources = [
        row["provider"] for row in provider_rows
        if row["provider_id"] in {"otx", "virustotal"}
        and any(item.get("verdict") in {"match", "malicious", "suspicious"} for item in row.get("observations", []))
    ]
    if adverse_ioc_sources:
        add("Immediate", "Block confirmed malicious IP, domain, URL, or hash in firewall, DNS, proxy, and EDR controls.", "External reputation evidence matched an IOC.", adverse_ioc_sources)

    vulnerable_sources = [
        row["provider"] for row in provider_rows
        if row["provider_id"] in {"osv", "nvd"}
        and any(item.get("verdict") == "vulnerable" for item in row.get("observations", []))
    ]
    if vulnerable_sources:
        add("High", "Patch or mitigate the affected product/package and verify the installed version after remediation.", "The supplied vulnerability reference was confirmed.", vulnerable_sources)

    family_actions = {
        "DDoS": "Enable upstream DDoS filtering, rate limiting, and temporary source blocking.",
        "DoS": "Apply rate limiting, isolate the source, and validate service capacity and availability.",
        "MQTT": "Restrict MQTT broker access, rotate credentials, and enforce TLS and topic ACLs.",
        "Recon": "Block the scanning source and review adjacent firewall logs for targeted ports and assets.",
        "Spoofing": "Inspect ARP tables, enable Dynamic ARP Inspection, and isolate the suspected switch segment.",
    }
    if family in family_actions:
        add("High", family_actions[family], f"CatBoost classified the flow as {family}.", ["CICIoMT2024 CatBoost"])

    add("Review", "Preserve the original event and enrichment JSON for analyst review and audit.", "Maintain evidence and traceability.", ["Local SOC policy"])
    return actions[:5]


def analyze(payload: Mapping[str, Any]) -> dict[str, Any]:
    event = flatten_event(payload)
    prediction = model_service.predict(event)
    evidence = runner.run(enrich_event(event))
    provider_rows = summarize_provider_evidence(evidence, intelligence.status()["sources"])

    model_attack_score = attack_probability(prediction)
    cti_score = max(
        (
            float(item.get("confidence", 0.0) or 0.0)
            for item in evidence
            if item.get("verdict") in {"malicious", "vulnerable"}
        ),
        default=0.0,
    )
    asset_criticality = min(max(float(event.get("asset_criticality", 0.8)), 0.0), 1.0)
    risk_score = round(100 * (0.60 * model_attack_score + 0.25 * cti_score + 0.15 * asset_criticality), 2)
    risk_level = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 40 else "low"
    action_rows = recommendations(event, prediction, provider_rows, risk_score)

    result = {
        "investigation_id": secrets.token_hex(8),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "prediction": prediction,
        "indicator_evidence": evidence,
        "provider_evidence": provider_rows,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "attack_probability": round(model_attack_score, 6),
        "predicted_class_confidence": round(float(prediction["confidence"]), 6),
        "is_threat": int(prediction["predicted_family"] != "Benign" or cti_score > 0.2),
        "recommended_actions": action_rows,
        "source_coverage": {
            row["provider_id"]: {
                "queried": row["queried"],
                "available": row["available"],
                "status": row["status"],
            }
            for row in provider_rows
        },
    }
    with RESULTS_PATH.open("a", encoding="utf-8") as output:
        output.write(json.dumps({"event": event, "result": result}, ensure_ascii=False, default=str) + "\n")
    return result


def dashboard_log(event: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
    now = datetime.now()
    prediction = result["prediction"]
    source_ip = str(event.get("source_ip") or event.get("src_ip") or "0.0.0.0")
    destination = str(event.get("destination_ip") or event.get("dst_ip") or event.get("product") or "hospital asset")
    provider_rows = list(result.get("provider_evidence") or [])
    otx_match = any(
        row.get("provider_id") == "otx"
        and any(observation.get("verdict") == "match" for observation in row.get("observations") or [])
        for row in provider_rows
    )
    cti_verdicts = {
        str(item.get("verdict") or "unknown")
        for item in result.get("indicator_evidence") or []
    }
    if cti_verdicts & {"malicious", "vulnerable"}:
        intel_verdict = "CTI threat evidence confirmed"
    elif cti_verdicts:
        intel_verdict = "CTI checked — no confirmed threat evidence"
    else:
        intel_verdict = "CTI not applicable — no compatible indicator"
    sharing_classification = normalize_tlp(
        event.get("sharing_classification") or event.get("tlp"),
        default="TLP:AMBER",
    )
    log = {
        "log_id": f"AI-{now.strftime('%H%M%S')}-{random.randint(100, 999)}",
        "report_type": "live_incident_investigation",
        "report_type_label": "Live incident investigation",
        "date": now.strftime("%Y-%m-%d"),
        "timestamp": now.strftime("%H:%M:%S"),
        "category": "IoMT network flows",
        "traffic_class": prediction["predicted_family"],
        "department": str(event.get("department") or "IoMT security test"),
        "source_ip": source_ip,
        "destination_target": destination,
        "data_mb": 0.0,
        "data_unit": "KB",
        "is_threat": result["is_threat"],
        "is_in_otx": otx_match,
        "risk_level": result["risk_level"],
        "severity": result["risk_level"],
        "risk_probability": result["risk_score"] / 100.0,
        "attack_probability": result["attack_probability"],
        "model_probability": prediction["confidence"],
        "predicted_class_confidence": prediction["confidence"],
        "features": prediction.get("features") or {},
        "class_probabilities": prediction.get("probabilities") or {},
        "intel_verdict": intel_verdict,
        "tlp": sharing_classification,
        "sharing_classification": sharing_classification,
        "provider_evidence": provider_rows,
        "indicator_evidence": result["indicator_evidence"],
        "recommended_actions": result["recommended_actions"],
        "risk_reasons": [
            f"CatBoost prediction: {prediction['predicted_family']} ({prediction['confidence']:.1%}).",
            f"Combined model, CTI, and asset risk: {result['risk_score']:.1f}/100.",
        ],
        "model_details": prediction,
        "investigation_id": result["investigation_id"],
        "live_evidence_endpoint": (
            f"/api/investigations/{result['investigation_id']}/live-evidence"
        ),
        "evaluation_mode": False,
        "observed_time": str(event.get("observed_time") or event.get("timestamp") or now.isoformat()),
    }
    recent_alerts.appendleft(log)
    return log


def analyze_and_record(payload: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    event = flatten_event(payload)
    result = analyze(event)
    log = dashboard_log(event, result)
    try:
        investigation_id = database.persist(event, result, log)
        result["persistence"] = {
            "status": "stored",
            "investigation_id": investigation_id,
            "backend": database.status()["backend"],
        }
    except Exception as exc:
        result["persistence"] = {"status": "error", "error": str(exc)[:300]}
    return event, result, log


async def enrich_pcap_references(
    indicator_rows: list[Mapping[str, Any]],
    cve_ids: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Enrich only references that are attributable to this capture/asset."""

    ioc_tasks = [intelligence.enrich_indicator(str(row["value"])) for row in indicator_rows]
    cve_tasks = [intelligence.enrich_indicator(cve_id) for cve_id in cve_ids]
    ioc_results = await asyncio.gather(*ioc_tasks, return_exceptions=True) if ioc_tasks else []
    cve_results = await asyncio.gather(*cve_tasks, return_exceptions=True) if cve_tasks else []

    def normalize(results: list[Any], references: list[str]) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for reference, result in zip(references, results):
            if isinstance(result, Exception):
                output.append({
                    "indicator": reference,
                    "verdict": "error",
                    "confidence": 0.0,
                    "sources": {},
                    "message": str(result)[:300],
                })
            else:
                output.append(result)
        return output

    return (
        normalize(ioc_results, [str(row["value"]) for row in indicator_rows]),
        normalize(cve_results, cve_ids),
    )


def pcap_recommendations(
    model_result: Mapping[str, Any],
    intelligence_rows: list[Mapping[str, Any]],
) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []
    malicious_iocs = [
        str(row.get("indicator"))
        for row in intelligence_rows
        if row.get("verdict") == "malicious"
    ]
    vulnerable = [
        str(row.get("indicator"))
        for row in intelligence_rows
        if row.get("verdict") == "vulnerable"
    ]
    if malicious_iocs:
        actions.append({
            "priority": "Immediate",
            "action": "Block confirmed malicious public indicators in firewall, DNS, proxy, and EDR controls.",
            "reason": f"Live CTI matched {len(malicious_iocs)} capture indicator(s).",
        })
    if vulnerable:
        actions.append({
            "priority": "High",
            "action": "Patch or mitigate the confirmed CVE on the attributable asset, then verify the installed version.",
            "reason": f"OSV/NVD confirmed {len(vulnerable)} supplied vulnerability reference(s).",
        })
    family = str(model_result.get("predicted_family") or "")
    family_actions = {
        "DDoS": "Enable upstream DDoS filtering and rate limiting.",
        "DoS": "Rate-limit and isolate the suspected source while validating service availability.",
        "MQTT": "Restrict broker access, rotate credentials, and enforce TLS/topic ACLs.",
        "Recon": "Block the scanner and review adjacent firewall logs for targeted assets and ports.",
        "Spoofing": "Inspect ARP tables, enable Dynamic ARP Inspection, and isolate the switch segment.",
    }
    if family in family_actions:
        actions.append({
            "priority": "High",
            "action": family_actions[family],
            "reason": f"CatBoost classified the supplied 12-feature row as {family}.",
        })
    actions.append({
        "priority": "Review",
        "action": "Preserve the original PCAP, its SHA-256, extraction result, and provider responses for analyst review.",
        "reason": "Packet provenance and reproducibility are required for incident handling.",
    })
    return actions


def analyze_pcap_file(
    source: Path,
    *,
    display_name: str,
    max_packets: int,
    max_indicators: int,
    feature_payload: Mapping[str, Any] | None,
    cve_ids: list[str],
) -> dict[str, Any]:
    extracted = extract_pcap_indicators(source, max_packets=max_packets, max_flows=5_000)
    selected_indicators = list(extracted["api_ready_indicators"])[:max_indicators]
    ioc_evidence, vulnerability_evidence = runner.run(
        enrich_pcap_references(selected_indicators, cve_ids),
        timeout=max(90.0, 25.0 * (len(selected_indicators) + len(cve_ids))),
    )

    feature_source = "manual" if feature_payload is not None else None
    feature_extraction_error: str | None = None
    if feature_payload is None:
        try:
            feature_payload = compute_flow_features(source, max_packets=max_packets)
            feature_source = "computed_from_pcap"
        except Exception as exc:  # noqa: BLE001 - surfaced as a "not_run" reason, never invented
            feature_payload = None
            feature_extraction_error = str(exc)

    model_result: dict[str, Any]
    if feature_payload is None:
        model_result = {
            "status": "not_run",
            "reason": (
                f"The 12 aggregated flow features could not be computed from this capture "
                f"({feature_extraction_error}). No model prediction was invented."
                if feature_extraction_error
                else "The PCAP supplies packet evidence, but not the exact 12 aggregated flow features "
                "required by the deployed CatBoost artifact. No model prediction was invented."
            ),
            "required_features": list(model_service.features),
        }
    else:
        try:
            prediction = model_service.predict(feature_payload)
            model_result = {"status": "completed", **prediction}
        except ValueError as exc:
            model_result = {
                "status": "not_run",
                "reason": str(exc),
                "required_features": list(model_service.features),
            }

    all_intelligence = [*ioc_evidence, *vulnerability_evidence]
    cti_score = max(
        (
            float(row.get("confidence", 0.0) or 0.0)
            for row in all_intelligence
            if row.get("verdict") in {"malicious", "vulnerable"}
        ),
        default=0.0,
    )
    model_score = attack_probability(model_result) if model_result.get("status") == "completed" else 0.0
    if model_result.get("status") == "completed":
        risk_score = round(100.0 * (0.65 * model_score + 0.35 * cti_score), 2)
    else:
        risk_score = round(100.0 * cti_score, 2)
    risk_level = (
        "critical" if risk_score >= 80
        else "high" if risk_score >= 60
        else "medium" if risk_score >= 40
        else "low" if risk_score > 0
        else "info"
    )

    investigation_id = f"PCAP-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(3)}"
    report = {
        "investigation_id": investigation_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "capture_summary": {
            "file_name": display_name,
            "sha256": sha256_file(source),
            "file_size": source.stat().st_size,
            "packets_read": extracted["packets_read"],
            "bytes_read": extracted["bytes_read"],
            "truncated": extracted["truncated"],
            "flow_count": extracted["flow_count"],
            "indicator_count": len(extracted["indicators"]),
            "public_indicator_count": len(extracted["api_ready_indicators"]),
            "queried_indicator_count": len(selected_indicators),
            "protocol_counts": extracted["protocol_counts"],
        },
        "model": model_result,
        "model_feature_source": feature_source,
        "pcap_evidence": {
            "indicators": extracted["indicators"][:100],
            "flows_preview": extracted["flows"][:25],
            "query_limit": max_indicators,
        },
        "threat_intelligence": {
            "iot_indicators": ioc_evidence,
            "routing": "Public IP/domain/URL/hash references are sent only to OTX and VirusTotal.",
        },
        "asset_vulnerability": {
            "supplied_cves": cve_ids,
            "evidence": vulnerability_evidence,
            "routing": (
                "OSV and NVD are queried only for CVEs supplied as attributable asset metadata; "
                "a CVE is never guessed from packet statistics."
            ),
        },
        "risk": {
            "score": risk_score,
            "level": risk_level,
            "model_component_available": model_result.get("status") == "completed",
            "cti_component_available": bool(all_intelligence),
        },
    }
    report["recommendations"] = pcap_recommendations(model_result, all_intelligence)
    database.persist_pcap_investigation(report)
    with PCAP_RESULT_PATH.open("a", encoding="utf-8") as output:
        output.write(json.dumps(report, ensure_ascii=False, default=str) + "\n")
    return report


app = Flask(__name__, static_folder=str(DIST_DIR), static_url_path="")
app.config["JSON_SORT_KEYS"] = False
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_PCAP_UPLOAD_MB", "256")) * 1024 * 1024

IS_MANAGED_DEPLOYMENT = bool(os.getenv("RENDER"))
required_auth_settings = ("ADMIN_EMAIL", "ADMIN_PASSWORD", "DEV_OTP_CODE", "FLASK_SECRET_KEY")
missing_auth_settings = [name for name in required_auth_settings if not os.getenv(name)]
if IS_MANAGED_DEPLOYMENT and missing_auth_settings:
    raise RuntimeError(
        "Secure deployment blocked: configure these secret environment variables: "
        + ", ".join(missing_auth_settings)
    )

app.secret_key = os.getenv("FLASK_SECRET_KEY") or os.getenv("ADMIN_PASSWORD") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(os.getenv("ADMIN_SESSION_MINUTES", "30"))),
)
sock = Sock(app)

PUBLIC_API_PATHS = {
    "/api/health",
    "/api/admin/login",
    "/api/admin/verify-otp",
    "/api/admin/session",
}


@app.before_request
def require_admin_session() -> Any:
    if request.path.startswith("/api/") and request.path not in PUBLIC_API_PATHS:
        if not session.get("admin_authenticated"):
            return jsonify({"detail": "Authentication required."}), 401
    return None


@app.after_request
def add_security_headers(response: Any) -> Any:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.path.startswith("/api/") or request.path == "/":
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/health")
def health() -> Any:
    return jsonify({
        "status": "ok",
        "framework": "Flask",
        "access": "restricted",
    })


@app.get("/api/database/status")
def database_status() -> Any:
    return jsonify(database.status())


@app.get("/api/model")
def model_info() -> Any:
    return jsonify(model_service.metadata)


@app.get("/api/evaluation-samples")
def evaluation_samples() -> Any:
    try:
        rows = load_official_test_replay()
    except (FileNotFoundError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 500

    reports = [evaluation_dashboard_log(row) for row in rows]
    family_counts: dict[str, int] = {}
    correct = 0
    for row in rows:
        family = str(row["true_family"])
        family_counts[family] = family_counts.get(family, 0) + 1
        correct += int(bool(row["correct"]))

    total = len(rows)
    return jsonify({
        "samples": reports,
        "summary": {
            "total": total,
            "correct": correct,
            "incorrect": total - correct,
            "accuracy": round(correct / total, 6) if total else 0.0,
            "rows_per_family": family_counts,
            "sampling": "50 unique rows per family, sampled without replacement",
            "dataset": "CICIoMT2024",
            "split": "Official TEST — never used for training or balancing",
        },
    })


@app.post("/api/evaluation-samples/<sample_id>/live-evidence")
def evaluation_sample_live_evidence(sample_id: str) -> Any:
    row = next(
        (item for item in load_official_test_replay() if str(item["sample_id"]) == sample_id),
        None,
    )
    if row is None:
        return jsonify({"error": "Evaluation sample was not found."}), 404

    # A report refresh is deliberately live. Do not reuse the in-memory CTI
    # cache or the evidence snapshot previously rendered for this sample.
    force_refresh = True
    connectivity = run_provider_connectivity_check(force_refresh=force_refresh)
    checked_at = str(connectivity["checked_at"])
    evidence = runner.run(
        enrich_evaluation_api_context(row, force_refresh=force_refresh),
        timeout=120.0,
    )
    provider_rows = summarize_provider_evidence(
        evidence,
        intelligence.status()["sources"],
    )
    for provider in provider_rows:
        for observation in provider.get("observations") or []:
            observation["attributable_to_log"] = False
    fused_risk = live_fused_risk(evaluation_dashboard_log(row), evidence)
    context_ready = bool(evidence)
    return jsonify({
        "sample_id": sample_id,
        "checked_at": checked_at,
        "evidence_mode": "capture_and_dependency_context" if context_ready else "connectivity_only",
        "all_four_connected": bool(connectivity["all_four_connected"]),
        "all_four_available": bool(connectivity["all_four_connected"]),
        "provider_evidence": provider_rows if context_ready else evaluation_provider_evidence(row),
        "indicator_evidence": evidence,
        "live_query": context_ready,
        "connectivity_check": True,
        "provider_findings_used_as_evidence": False,
        "cache_used": False,
        "live_fused_risk": fused_risk["score"],
        "live_risk_level": fused_risk["level"],
        "live_cti_score": fused_risk["cti_score"],
        "risk_adjustment_applied": fused_risk["applied"],
        "live_risk_reason": fused_risk["reason"],
        "message": (
            f"All four APIs were queried live at {checked_at} using real project context. "
            "OTX and VirusTotal received a public indicator extracted from the official PCAP; "
            "OSV received an exact deployed dependency version; NVD received any real CVE "
            "aliases returned by OSV. These findings provide investigation details and response "
            "guidance, but they are not native columns of this numeric TEST row and do not alter "
            "its CatBoost evaluation result."
            if context_ready
            else f"Live API connectivity was checked at {checked_at}, but this sample has no "
            "attached API context. Regenerate the evaluation artifact with the API-context script."
        ),
    })


@app.post("/api/investigations/<investigation_id>/live-evidence")
def investigation_live_evidence(investigation_id: str) -> Any:
    """Refresh CTI for one persisted report without storing the new response.

    The stored dashboard snapshot supplies only indicators that belonged to the
    original investigation.  Provider responses are fetched live and returned
    to the open report, but are not written back to PostgreSQL/SQLite.
    """

    log = next(
        (
            item
            for item in database.list_dashboard_logs(500)
            if str(item.get("investigation_id") or "") == investigation_id
        ),
        None,
    )
    if log is None:
        return jsonify({"error": "Investigation was not found."}), 404

    indicators = list(dict.fromkeys(
        str(item.get("indicator") or "").strip()
        for item in (log.get("indicator_evidence") or [])
        if str(item.get("indicator") or "").strip()
        and (item.get("provenance") or {}).get("attributable_to_log", True) is not False
    ))
    event: dict[str, Any] = {
        **dict(log.get("features") or {}),
        "source_ip": log.get("source_ip"),
        "destination_ip": log.get("destination_target"),
        "indicators": indicators,
    }
    checked_at = datetime.now(timezone.utc).isoformat()
    evidence = runner.run(
        enrich_event(event, force_refresh=True),
        timeout=120,
    )
    states = intelligence.status()["sources"]
    provider_evidence = summarize_provider_evidence(evidence, states)
    for provider in provider_evidence:
        state = states.get(provider["provider_id"]) or {}
        provider["connection_status"] = str(state.get("status") or "unknown")
        provider["connection_verified_at"] = state.get("last_success")
        provider["connection_error"] = state.get("last_error")
        provider["lookup_mode"] = "live_api"
    fused_risk = live_fused_risk(log, evidence)
    live_verdicts = {
        str(item.get("verdict") or "unknown").lower()
        for item in evidence
    }
    if live_verdicts & {"malicious", "vulnerable"}:
        intel_verdict = "Live CTI threat evidence confirmed for this event"
    elif evidence:
        intel_verdict = "Live CTI checked — no confirmed threat evidence"
    else:
        intel_verdict = "CTI not applicable — no compatible event indicator"
    live_prediction = {
        "predicted_family": str(log.get("traffic_class") or "Unknown"),
    }
    live_actions = recommendations(event, live_prediction, provider_evidence, fused_risk["score"])

    return jsonify({
        "investigation_id": investigation_id,
        "checked_at": checked_at,
        "evidence_mode": "event_attributed_live" if evidence else "connectivity_only",
        "all_four_connected": all(
            str((states.get(provider) or {}).get("status")) == "live"
            for provider in ("otx", "virustotal", "osv", "nvd")
        ),
        "provider_evidence": provider_evidence,
        "indicator_evidence": evidence,
        "live_query": True,
        "cache_used": False,
        "live_fused_risk": fused_risk["score"],
        "live_risk_level": fused_risk["level"],
        "live_cti_score": fused_risk["cti_score"],
        "risk_adjustment_applied": fused_risk["applied"],
        "live_risk_reason": fused_risk["reason"],
        "intel_verdict": intel_verdict,
        "recommended_actions": live_actions,
        "message": (
            f"Fresh live provider queries completed at {checked_at} for this report's own indicators; "
            "the returned evidence was not loaded from or written back to the stored report."
            if evidence
            else (
                f"Fresh connectivity check completed at {checked_at}, but this report has no "
                "compatible public indicator."
            )
        ),
    })


@app.get("/api/intelligence/status")
def intelligence_status() -> Any:
    return jsonify(intelligence.status())


connectivity_check_cache: dict[str, Any] = {}
connectivity_check_lock = threading.Lock()


def run_provider_connectivity_check(*, force_refresh: bool) -> dict[str, Any]:
    """Verify provider reachability without attaching probe findings to a log.

    OTX and VirusTotal require an IoC-shaped request, while OSV and NVD require
    a vulnerability reference.  The two public probes below are used only to
    verify HTTPS/authentication and their findings are deliberately discarded.
    The result is cached to protect provider quotas when several reports open.
    """

    now = time.monotonic()
    with connectivity_check_lock:
        cached_at = float(connectivity_check_cache.get("cached_at") or 0.0)
        if not force_refresh and now - cached_at < 600 and connectivity_check_cache.get("result"):
            return dict(connectivity_check_cache["result"])

        async def check_sources() -> None:
            await asyncio.gather(
                intelligence.enrich_indicator("8.8.8.8", force_refresh=force_refresh),
                intelligence.enrich_indicator("CVE-2021-44228", force_refresh=force_refresh),
            )

        runner.run(check_sources(), timeout=120)
        checked_at = datetime.now(timezone.utc).isoformat()
        states = intelligence.status()["sources"]
        sources = {
            provider: {
                "name": state.get("name"),
                "configured": bool(state.get("configured")),
                "status": state.get("status"),
                "connected": state.get("status") == "live",
                "last_success": state.get("last_success"),
                "last_error": state.get("last_error"),
                "latency_ms": state.get("latency_ms"),
            }
            for provider, state in states.items()
        }
        result = {
            "checked_at": checked_at,
            "all_four_connected": all(item["connected"] for item in sources.values()),
            "sources": sources,
            "probe_results_attached_to_logs": False,
        }
        connectivity_check_cache.update({"cached_at": now, "result": result})
        return result


@app.post("/api/intelligence/connectivity-check")
def intelligence_connectivity_check() -> Any:
    payload = request.get_json(silent=True) or {}
    result = run_provider_connectivity_check(
        force_refresh=bool(payload.get("force_refresh", False)),
    )
    return jsonify(result)


@app.post("/api/intelligence/lookup")
def intelligence_lookup() -> Any:
    payload = request.get_json(silent=True) or {}
    indicator = str(payload.get("indicator") or "").strip()
    if not indicator:
        return jsonify({"error": "indicator is required"}), 422
    try:
        return jsonify(runner.run(intelligence.enrich_indicator(indicator)))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 422


@app.get("/api/vulnerabilities/posture")
def vulnerability_posture() -> Any:
    return jsonify(intelligence.posture())


@app.post("/api/vulnerabilities/refresh")
def vulnerability_refresh() -> Any:
    return jsonify(runner.run(intelligence.refresh_posture(), timeout=240.0))


@app.post("/api/predict")
@app.post("/api/analyze")
def predict() -> Any:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "A JSON event object is required."}), 400
    try:
        _event, result, log = analyze_and_record(payload)
        return jsonify({**result, "dashboard_log": log})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 422
    except Exception as exc:
        return jsonify({"error": f"Investigation failed: {str(exc)[:300]}"}), 500


@app.get("/api/integration-sample")
def integration_sample() -> Any:
    return jsonify(load_integration_sample())


@app.post("/api/integration-sample/run")
def run_integration_sample() -> Any:
    event, result, log = analyze_and_record(load_integration_sample())
    return jsonify({"event": event, "result": result, "dashboard_log": log})


@app.get("/api/alerts")
def alerts() -> Any:
    limit = min(max(int(request.args.get("limit", 100)), 1), 500)
    return jsonify({"alerts": database.list_alerts(limit), "storage": database.status()["backend"]})


@app.get("/api/investigations")
def investigations() -> Any:
    limit = min(max(int(request.args.get("limit", 100)), 1), 500)
    return jsonify({"investigations": database.list_dashboard_logs(limit), "storage": database.status()["backend"]})


@app.get("/api/pcap/samples")
def pcap_samples() -> Any:
    samples = []
    for sample_id, path in PCAP_SAMPLE_FILES.items():
        if path.is_file():
            samples.append({
                "id": sample_id,
                "label": sample_id.title(),
                "file_name": path.name,
                "file_size": path.stat().st_size,
            })
    return jsonify({"samples": samples})


@app.get("/api/pcap/investigations")
def pcap_investigations() -> Any:
    limit = min(max(int(request.args.get("limit", 25)), 1), 100)
    return jsonify({
        "investigations": database.list_pcap_investigations(limit),
        "storage": database.status()["backend"],
    })


@app.post("/api/pcap/analyze")
def analyze_pcap_upload() -> Any:
    """Analyze an uploaded capture or one curated local demonstration file."""

    sample_id = str(request.form.get("sample_id") or "").strip().lower()
    upload = request.files.get("pcap")
    if not sample_id and (upload is None or not upload.filename):
        return jsonify({"error": "Choose a project capture or upload a .pcap/.pcapng file."}), 422
    if sample_id and sample_id not in PCAP_SAMPLE_FILES:
        return jsonify({"error": "Unknown project capture."}), 422

    try:
        max_packets = min(max(int(request.form.get("max_packets", 50_000)), 100), 250_000)
        max_indicators = min(max(int(request.form.get("max_indicators", 10)), 1), 20)
    except ValueError:
        return jsonify({"error": "Packet and indicator limits must be integers."}), 422

    raw_features = str(request.form.get("features_json") or "").strip()
    feature_payload = None
    if raw_features:
        try:
            decoded = json.loads(raw_features)
        except json.JSONDecodeError:
            return jsonify({"error": "features_json must contain valid JSON."}), 422
        if not isinstance(decoded, Mapping):
            return jsonify({"error": "features_json must be a JSON object."}), 422
        feature_payload = decoded

    raw_cves = str(request.form.get("cve_ids") or "")
    cve_ids = list(dict.fromkeys(
        value.strip().upper()
        for value in raw_cves.replace(";", ",").split(",")
        if value.strip()
    ))[:10]
    invalid_cves = [value for value in cve_ids if not value.startswith("CVE-")]
    if invalid_cves:
        return jsonify({"error": f"Invalid CVE reference: {invalid_cves[0]}"}), 422

    try:
        if sample_id:
            path = PCAP_SAMPLE_FILES[sample_id]
            if not path.is_file():
                return jsonify({"error": "The selected project capture is missing."}), 404
            report = analyze_pcap_file(
                path,
                display_name=path.name,
                max_packets=max_packets,
                max_indicators=max_indicators,
                feature_payload=feature_payload,
                cve_ids=cve_ids,
            )
        else:
            safe_name = secure_filename(str(upload.filename))
            suffix = Path(safe_name).suffix.lower()
            if suffix not in {".pcap", ".pcapng"}:
                return jsonify({"error": "Only .pcap and .pcapng files are accepted."}), 422
            with tempfile.TemporaryDirectory(prefix="cti-pcap-") as temp_dir:
                path = Path(temp_dir) / safe_name
                upload.save(path)
                if not path.is_file() or path.stat().st_size == 0:
                    return jsonify({"error": "The uploaded capture is empty."}), 422
                report = analyze_pcap_file(
                    path,
                    display_name=safe_name,
                    max_packets=max_packets,
                    max_indicators=max_indicators,
                    feature_payload=feature_payload,
                    cve_ids=cve_ids,
                )
        return jsonify(report)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        return jsonify({"error": str(exc)[:500]}), 422
    except Exception as exc:
        return jsonify({"error": f"PCAP investigation failed: {str(exc)[:400]}"}), 500


ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@hospital.com").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin12345")
DEV_OTP_CODE = os.getenv("DEV_OTP_CODE", "").strip()
OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", "300"))
otp_store: dict[str, dict[str, Any]] = {}


@app.post("/api/admin/login")
def admin_login() -> Any:
    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email") or "").strip().lower()
    password = str(payload.get("password") or "")
    if not (hmac.compare_digest(email, ADMIN_EMAIL) and hmac.compare_digest(password, ADMIN_PASSWORD)):
        time.sleep(0.35)
        return jsonify({"detail": "Invalid admin credentials."}), 401

    session.clear()
    session["pending_admin_email"] = email
    code = DEV_OTP_CODE or f"{secrets.randbelow(1_000_000):06d}"
    otp_store[email] = {"code": code, "expires_at": time.time() + OTP_TTL_SECONDS}
    if os.getenv("FLASK_DEBUG", "false").lower() == "true":
        print(f"Healthcare SOC OTP generated for {email}.")
    return jsonify({"message": "OTP generated.", "expires_in": OTP_TTL_SECONDS})


@app.post("/api/admin/verify-otp")
def verify_otp() -> Any:
    payload = request.get_json(silent=True) or {}
    email = str(session.get("pending_admin_email") or "").strip().lower()
    code = str(payload.get("code") or "").strip()
    entry = otp_store.get(email)
    if not entry or time.time() > entry["expires_at"]:
        otp_store.pop(email, None)
        session.clear()
        return jsonify({"detail": "No active or valid verification code."}), 400
    if not hmac.compare_digest(code, entry["code"]):
        return jsonify({"detail": "Verification code is not valid."}), 401

    otp_store.pop(email, None)
    session.clear()
    session.permanent = True
    session["admin_authenticated"] = True
    session["admin_email"] = email
    return jsonify({"message": "Login verified.", "email": email})


@app.get("/api/admin/session")
def admin_session() -> Any:
    return jsonify({
        "authenticated": bool(session.get("admin_authenticated")),
        "email": session.get("admin_email"),
    })


@app.post("/api/admin/logout")
def admin_logout() -> Any:
    session.clear()
    return jsonify({"message": "Signed out."})


@sock.route("/ws/live-logs")
def live_logs(websocket: Any) -> None:
    if not session.get("admin_authenticated"):
        websocket.send(json.dumps({"error": "Authentication required."}))
        websocket.close()
        return
    # Opening the dashboard must not manufacture investigations or consume
    # provider quotas. The socket only delivers records persisted elsewhere.
    existing = database.list_dashboard_logs(100)
    seen = {
        str(row.get("investigation_id") or row.get("log_id"))
        for row in existing
        if row.get("investigation_id") or row.get("log_id")
    }
    websocket.send(json.dumps({"type": "heartbeat"}))
    while True:
        try:
            rows = database.list_dashboard_logs(100)
            for log in reversed(rows):
                identity = str(log.get("investigation_id") or log.get("log_id") or "")
                if identity and identity not in seen:
                    websocket.send(json.dumps(log, ensure_ascii=False, default=str))
                    seen.add(identity)
            websocket.send(json.dumps({"type": "heartbeat"}))
            time.sleep(max(3, int(os.getenv("LIVE_LOG_SECONDS", "5"))))
        except Exception as exc:
            websocket.send(json.dumps({"error": str(exc)[:240]}))
            time.sleep(8)


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def frontend(path: str) -> Any:
    candidate = DIST_DIR / path
    if path and candidate.is_file():
        return send_from_directory(DIST_DIR, path)
    return send_from_directory(DIST_DIR, "index.html")


if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "8000")),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
        use_reloader=False,
    ) 