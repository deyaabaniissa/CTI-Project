"""Normalize CTI evidence and derive evidence-linked response guidance."""

from __future__ import annotations

from typing import Any, Mapping, Sequence


PROVIDER_NAMES = {
    "otx": "AlienVault OTX",
    "virustotal": "VirusTotal",
    "osv": "OSV",
    "nvd": "NIST NVD",
}


def _integer(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _number(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _observation(provider: str, evidence: Mapping[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    indicator = str(evidence.get("indicator") or "unknown")
    indicator_type = str(evidence.get("type") or "unknown")
    if payload.get("error"):
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "verdict": "error",
            "result": f"Lookup failed: {str(payload['error'])[:180]}",
            "metrics": {},
        }

    if provider == "otx":
        pulses = _integer(payload.get("pulse_count"))
        reputation = _integer(payload.get("reputation"))
        validations = _integer(payload.get("validation_count"))
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "verdict": "match" if pulses else "no_match",
            "result": f"{pulses} OTX pulse(s); reputation {reputation}; {validations} validation record(s).",
            "metrics": {"pulse_count": pulses, "reputation": reputation, "validation_count": validations},
        }

    if provider == "virustotal":
        malicious = _integer(payload.get("malicious"))
        suspicious = _integer(payload.get("suspicious"))
        harmless = _integer(payload.get("harmless"))
        total = _integer(payload.get("total_engines"))
        verdict = "malicious" if malicious else ("suspicious" if suspicious else "clean")
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "verdict": verdict,
            "result": (
                f"{malicious} malicious, {suspicious} suspicious, and {harmless} harmless "
                f"engine result(s) out of {total}."
            ),
            "metrics": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "total_engines": total,
                "reputation": _integer(payload.get("reputation")),
            },
        }

    if provider == "osv":
        found = bool(payload.get("found"))
        advisory = str(payload.get("id") or indicator)
        affected = _integer(payload.get("affected_packages"))
        summary = str(payload.get("summary") or "No OSV advisory summary returned.")
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "verdict": "vulnerable" if found else "not_found",
            "result": (
                f"{advisory} confirmed; {affected} affected package record(s). {summary}"
                if found
                else f"{advisory} was not found in OSV."
            ),
            "metrics": {"found": found, "id": advisory, "affected_packages": affected},
        }

    records = list(payload.get("records") or [])
    max_cvss = max((_number(record.get("cvss")) for record in records), default=0.0)
    known_exploited = any(bool(record.get("known_exploited")) for record in records)
    cve_ids = [str(record.get("cve_id")) for record in records if record.get("cve_id")]
    required_actions = [
        str(record.get("required_action"))
        for record in records
        if str(record.get("required_action") or "").strip()
    ]
    severities = sorted({str(record.get("severity") or "UNKNOWN") for record in records})
    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "verdict": "vulnerable" if records else "not_found",
        "result": (
            f"{', '.join(cve_ids) or indicator} confirmed; maximum CVSS {max_cvss:.1f}; "
            f"severity {', '.join(severities) or 'UNKNOWN'}; known exploited: {'Yes' if known_exploited else 'No'}."
            if records
            else f"{indicator} was not found in NVD."
        ),
        "metrics": {
            "found": bool(records),
            "cve_ids": cve_ids,
            "max_cvss": max_cvss,
            "severities": severities,
            "known_exploited": known_exploited,
            "required_actions": required_actions,
        },
    }


def summarize_provider_evidence(
    indicator_evidence: Sequence[Mapping[str, Any]],
    provider_states: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return one explicit report row for every configured CTI provider."""

    rows: dict[str, dict[str, Any]] = {}
    for provider, name in PROVIDER_NAMES.items():
        state = provider_states.get(provider) or {}
        rows[provider] = {
            "provider_id": provider,
            "provider": name,
            "configured": bool(state.get("configured")),
            "applicable": False,
            "queried": False,
            "available": False,
            "status": "not_applicable",
            "result": "Not applicable to the indicator type in this log.",
            "observations": [],
        }

    for evidence in indicator_evidence:
        coverage = evidence.get("coverage") or {}
        sources = evidence.get("sources") or {}
        applicable = set(coverage.get("applicable_sources") or [])
        queried = set(coverage.get("queried_sources") or [])
        available = set(coverage.get("available_sources") or [])
        for provider, row in rows.items():
            row["applicable"] = bool(row["applicable"] or provider in applicable)
            row["queried"] = bool(row["queried"] or provider in queried)
            row["available"] = bool(row["available"] or provider in available)
            payload = sources.get(provider)
            if isinstance(payload, Mapping):
                row["observations"].append(_observation(provider, evidence, payload))

    for row in rows.values():
        if not row["applicable"]:
            continue
        if not row["configured"]:
            row["status"] = "not_configured"
            row["result"] = "Applicable, but the provider is not configured."
        elif not row["queried"]:
            row["status"] = "not_queried"
            row["result"] = "Applicable, but no query was completed."
        elif not row["available"]:
            row["status"] = "unavailable"
            row["result"] = "The provider was queried but did not return an available result."
        else:
            row["status"] = "available"
            row["result"] = " | ".join(
                f"{item['indicator']}: {item['result']}" for item in row["observations"]
            ) or "Provider returned an available response with no finding details."
    return list(rows.values())


def build_recommended_actions(
    event: Mapping[str, Any],
    score: Mapping[str, Any],
    enrichment: Mapping[str, Any],
    provider_evidence: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Derive log-specific actions from provider facts plus the local rule result.

    The providers supply evidence, not a complete incident-response plan. These
    actions are deterministic local policy linked to the evidence cited in each
    item. Any NVD/CISA required action returned by the API is preserved.
    """

    indicator = str(enrichment.get("indicator") or event.get("indicator") or "the observed indicator")
    indicator_type = str(enrichment.get("type") or "unknown")
    device = str(event.get("device_type") or event.get("device_id") or "the affected device")
    department = str(event.get("department") or event.get("location") or "the affected department")
    rule = score.get("rule_assessment") or {}
    attack_type = str(rule.get("attack_type") or "none")
    rule_id = str(rule.get("rule_id") or "behavioral model")
    actions: list[dict[str, Any]] = []

    def add(priority: str, action: str, problem: str, sources: Sequence[str], evidence: str) -> None:
        if action not in {item["action"] for item in actions}:
            actions.append(
                {
                    "priority": priority,
                    "action": action,
                    "problem": problem,
                    "evidence_sources": list(dict.fromkeys(sources)),
                    "evidence": evidence,
                }
            )

    matches: list[str] = []
    vulnerability_sources: list[str] = []
    nvd_required_actions: list[str] = []
    cve_ids: list[str] = []
    for provider in provider_evidence:
        for observation in provider.get("observations") or []:
            verdict = observation.get("verdict")
            if provider["provider_id"] in {"otx", "virustotal"} and verdict in {"match", "malicious", "suspicious"}:
                matches.append(provider["provider"])
            if provider["provider_id"] in {"osv", "nvd"} and verdict == "vulnerable":
                vulnerability_sources.append(provider["provider"])
            metrics = observation.get("metrics") or {}
            nvd_required_actions.extend(metrics.get("required_actions") or [])
            cve_ids.extend(metrics.get("cve_ids") or [])

    if matches:
        if indicator_type in {"md5", "sha1", "sha256"}:
            response = f"Quarantine files matching {indicator} on {device} and run an endpoint scan."
        elif indicator_type in {"domain", "url"}:
            response = f"Block {indicator} at DNS, proxy, and secure-web gateways; then search endpoint telemetry for access."
        else:
            response = f"Block {indicator} at the firewall and search hospital network telemetry for related connections."
        add(
            "Immediate",
            response,
            f"The indicator associated with this {department} log has adverse reputation evidence.",
            matches,
            f"Provider verdict for {indicator}: {enrichment.get('verdict', 'unknown')}.",
        )

    if vulnerability_sources:
        vulnerability_id = ", ".join(dict.fromkeys(cve_ids)) or indicator
        if nvd_required_actions:
            action = f"For {vulnerability_id}, apply the NVD/CISA action: {nvd_required_actions[0]}"
        else:
            action = f"Patch or upgrade the component affected by {vulnerability_id} on {device}, then verify the exposure is removed."
        add(
            "High",
            action,
            f"A vulnerability reference in this {department} log was confirmed by vulnerability databases.",
            vulnerability_sources,
            f"Confirmed vulnerability evidence for {vulnerability_id}; this is exposure evidence, not proof of active exploitation.",
        )

    response_by_attack = {
        "reconnaissance": f"Rate-limit and block the scanning source for this {device} event, then review adjacent firewall logs for targeted ports.",
        "unauthorized_access": f"Terminate unauthorized sessions, disable the affected account or device access, and review authentication logs for {department}.",
        "record_tampering": f"Restrict write access, preserve the affected record history, and restore unauthorized changes from an approved version.",
        "data_exfiltration": f"Stop the transfer, restrict the account or device involved, and verify whether protected hospital data left the environment.",
        "malware": f"Isolate {device}, quarantine the detected artifact, and perform endpoint triage before reconnecting it.",
        "privilege_escalation": f"Revoke the new privileges, suspend the initiating account, and review privileged activity in {department}.",
        "credential_access": "Reset the affected credentials, revoke active sessions, require MFA, and check for subsequent account use.",
        "removable_media": f"Disconnect the USB device, isolate {device}, and scan both media and endpoint before restoring access.",
        "command_and_control": f"Isolate {device}, block the observed destination, and review DNS and network telemetry for beaconing.",
        "policy_violation": f"Pause the risky operation and have the {department} owner validate whether it was authorized.",
        "account_anomaly": f"Validate the account activity with the {department} owner and review recent authentication events.",
        "system_anomaly": f"Inspect {device} and correlate the event with firewall, DNS, and endpoint telemetry from the same time window.",
    }
    if attack_type in response_by_attack:
        add(
            "Immediate" if score.get("is_threat") else "Review",
            response_by_attack[attack_type],
            str(rule.get("reason") or "The behavioral rule identified an event requiring investigation."),
            [f"Local rule {rule_id}"],
            f"Final classification: {score.get('final_classification', 'unknown')}; risk probability {float(score.get('probability', 0.0)):.1%}.",
        )

    if not actions:
        available = [row["provider"] for row in provider_evidence if row.get("available")]
        add(
            "Monitor",
            "Retain this event for audit and monitor for recurrence; no containment is indicated by the current evidence.",
            "No rule or available provider result confirms a threat for this log.",
            available or [f"Local rule {rule_id}"],
            f"Final classification: {score.get('final_classification', 'unknown')}.",
        )

    return actions[:4]
