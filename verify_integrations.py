"""Perform a key-safe live smoke test of all four intelligence providers."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from cti.intelligence import ThreatIntelligenceService
from cti.model import ThreatRiskEngine


PROJECT_ROOT = Path(__file__).resolve().parent
IOC_TEST_VALUE = "8.8.8.8"
VULNERABILITY_TEST_VALUE = "CVE-2020-1472"


async def main() -> int:
    service = ThreatIntelligenceService(PROJECT_ROOT)
    ioc_result, vulnerability_result = await asyncio.gather(
        service.enrich_indicator(IOC_TEST_VALUE),
        service.enrich_indicator(VULNERABILITY_TEST_VALUE),
    )
    results_by_route = {
        "ioc_reputation": ioc_result,
        "vulnerability_reference": vulnerability_result,
    }
    engine = ThreatRiskEngine(PROJECT_ROOT / "threat_model.pkl")
    threat_score = engine.score(
        {
            "event_time": "2026-08-01T12:00:00Z",
            "log_type": "system_device",
            "location": "Data Center",
            "department": "IT",
            "actor_role": "system device",
            "action": "Network Port Scan",
            "object_type": "system event",
            "device_type": "Firewall",
            "protocol": "TCP",
            "severity": "High",
            "status": "Blocked",
            "source_port": 49152,
            "dest_port": 443,
        },
        ioc_result,
        {},
    )
    exposure_score = engine.score(
        {
            "event_time": "2026-08-01T12:00:00Z",
            "log_type": "employee_activity",
            "location": "Ward",
            "department": "Nursing",
            "actor_role": "Nurse",
            "action": "Login",
            "object_type": "account",
            "device_type": "Nursing Station PC",
            "protocol": "unknown",
            "severity": "Low",
            "status": "Success",
        },
        vulnerability_result,
        {},
    )
    expected_routes = {
        "otx": "ioc_reputation",
        "virustotal": "ioc_reputation",
        "osv": "vulnerability_reference",
        "nvd": "vulnerability_reference",
    }
    provider_rows = []
    all_live = True
    states = service.status()["sources"]
    for provider, route in expected_routes.items():
        result = results_by_route[route]
        coverage = result.get("coverage") or {}
        source_payload = (result.get("sources") or {}).get(provider) or {}
        configured = provider in (coverage.get("configured_sources") or [])
        queried = provider in (coverage.get("queried_sources") or [])
        available = provider in (coverage.get("available_sources") or [])
        state = states[provider]
        passed = configured and queried and available and state.get("status") == "live"
        all_live = all_live and passed
        provider_rows.append(
            {
                "provider": state["name"],
                "route": route,
                "configured": configured,
                "queried": queried,
                "available": available,
                "status": state.get("status"),
                "latency_ms": state.get("latency_ms"),
                "passed": passed,
                "error": str(source_payload.get("error") or state.get("last_error") or "")[:200] or None,
            }
        )

    all_live = bool(
        all_live
        and engine.metadata.get("status") == "trained"
        and threat_score["is_threat"] == 1
        and exposure_score["is_threat"] == 0
        and exposure_score["evidence"]["external_verdict"] == "vulnerable"
    )

    safe_summary = {
        "overall": "passed" if all_live else "failed",
        "api_keys_displayed": False,
        "tests": {
            "ioc_reputation": {
                "indicator_type": ioc_result.get("type"),
                "verdict": ioc_result.get("verdict"),
                "coverage_complete": (ioc_result.get("coverage") or {}).get("complete"),
            },
            "vulnerability_reference": {
                "indicator_type": vulnerability_result.get("type"),
                "verdict": vulnerability_result.get("verdict"),
                "coverage_complete": (vulnerability_result.get("coverage") or {}).get("complete"),
            },
        },
        "providers": provider_rows,
        "decision_engine": {
            "model_artifact_status": engine.metadata.get("status"),
            "port_scan_with_clean_ioc": {
                "classification": threat_score["final_classification"],
                "is_threat": bool(threat_score["is_threat"]),
                "rule_id": threat_score["rule_assessment"]["rule_id"],
            },
            "normal_login_with_vulnerable_cve": {
                "classification": exposure_score["final_classification"],
                "is_threat": bool(exposure_score["is_threat"]),
                "external_verdict": exposure_score["evidence"]["external_verdict"],
            },
        },
    }
    print(json.dumps(safe_summary, indent=2))
    return 0 if all_live else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
