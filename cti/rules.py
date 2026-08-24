"""Auditable hospital-log labeling and runtime risk rules.

These rules create *synthetic supervision* from operational fields only. They
never inspect the supplied ``threat_db_match``, provider name, or threat
reference, and they are not a substitute for human-confirmed incident labels.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class RuleAssessment:
    label: str
    attack_type: str
    confidence: str
    rule_id: str
    reason: str
    risk_score: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


LABELING_RULES = [
    {
        "source": "Patient access",
        "rule_id": "PAT-001",
        "label": "threat",
        "attack_type": "unauthorized_access",
        "confidence": "High",
        "trigger": "Status is Unauthorized Attempt.",
        "rationale": "An explicit unauthorized attempt is a security incident even when access was prevented.",
    },
    {
        "source": "Patient access",
        "rule_id": "PAT-002",
        "label": "threat",
        "attack_type": "record_tampering",
        "confidence": "High",
        "trigger": "Delete succeeds or is authorized.",
        "rationale": "Successful deletion of patient information requires immediate investigation.",
    },
    {
        "source": "Patient access",
        "rule_id": "PAT-003",
        "label": "threat",
        "attack_type": "data_exfiltration",
        "confidence": "High",
        "trigger": "Facilities/HR role successfully exports, downloads, or shares patient information.",
        "rationale": "The role and high-volume data action are inconsistent with normal clinical duties.",
    },
    {
        "source": "Patient access",
        "rule_id": "PAT-010",
        "label": "suspicious",
        "attack_type": "policy_violation",
        "confidence": "Medium",
        "trigger": "A risky data action is denied, or an export/download/share occurs without a stronger rule.",
        "rationale": "The activity merits review but is not sufficient to confirm a threat.",
    },
    {
        "source": "Patient access",
        "rule_id": "PAT-100",
        "label": "benign",
        "attack_type": "none",
        "confidence": "High",
        "trigger": "No higher-priority patient-access rule matches.",
        "rationale": "The record has no defined high-risk behavioral combination.",
    },
    {
        "source": "Employee activity",
        "rule_id": "EMP-001",
        "label": "threat",
        "attack_type": "privilege_escalation",
        "confidence": "High",
        "trigger": "Privilege escalation request succeeds.",
        "rationale": "Successful privilege escalation is a high-impact account event.",
    },
    {
        "source": "Employee activity",
        "rule_id": "EMP-002",
        "label": "threat",
        "attack_type": "credential_access",
        "confidence": "High",
        "trigger": "A failed-login event is recorded with Success status.",
        "rationale": "This inconsistent combination can indicate an account-control bypass or logging anomaly.",
    },
    {
        "source": "Employee activity",
        "rule_id": "EMP-003",
        "label": "threat",
        "attack_type": "removable_media",
        "confidence": "High",
        "trigger": "A non-security role successfully connects a USB device.",
        "rationale": "Uncontrolled removable media can introduce malware or enable data removal.",
    },
    {
        "source": "Employee activity",
        "rule_id": "EMP-004",
        "label": "threat",
        "attack_type": "data_exfiltration",
        "confidence": "High",
        "trigger": "A non-billing/non-security employee successfully exports records.",
        "rationale": "Successful record export outside expected administrative/security functions is high risk.",
    },
    {
        "source": "Employee activity",
        "rule_id": "EMP-010",
        "label": "suspicious",
        "attack_type": "account_anomaly",
        "confidence": "Medium",
        "trigger": "Risky action, failed/blocked outcome, or Flagged for Review status without a stronger rule.",
        "rationale": "The event needs analyst review but does not independently confirm compromise.",
    },
    {
        "source": "Employee activity",
        "rule_id": "EMP-100",
        "label": "benign",
        "attack_type": "none",
        "confidence": "High",
        "trigger": "No higher-priority employee rule matches.",
        "rationale": "The activity fits the current normal-behavior definition.",
    },
    {
        "source": "System/device",
        "rule_id": "SYS-001",
        "label": "threat",
        "attack_type": "malware",
        "confidence": "High",
        "trigger": "Event type is Malware Signature Detected.",
        "rationale": "A malware signature is direct threat evidence, even if containment succeeded.",
    },
    {
        "source": "System/device",
        "rule_id": "SYS-002",
        "label": "threat",
        "attack_type": "reconnaissance",
        "confidence": "High",
        "trigger": "Event type is Network Port Scan.",
        "rationale": "Port scanning is defined as reconnaissance activity in this synthetic scenario set.",
    },
    {
        "source": "System/device",
        "rule_id": "SYS-003",
        "label": "threat",
        "attack_type": "unauthorized_access",
        "confidence": "High",
        "trigger": "Event type is Unauthorized Access Attempt.",
        "rationale": "An explicit unauthorized access attempt is a security incident.",
    },
    {
        "source": "System/device",
        "rule_id": "SYS-004",
        "label": "threat",
        "attack_type": "data_exfiltration",
        "confidence": "High",
        "trigger": "High/critical outbound data transfer succeeds.",
        "rationale": "A successful high-severity outbound transfer can indicate exfiltration.",
    },
    {
        "source": "System/device",
        "rule_id": "SYS-005",
        "label": "threat",
        "attack_type": "command_and_control",
        "confidence": "High",
        "trigger": "High/critical DNS anomaly is not blocked or quarantined.",
        "rationale": "Uncontained high-severity DNS anomalies can indicate command-and-control traffic.",
    },
    {
        "source": "System/device",
        "rule_id": "SYS-010",
        "label": "suspicious",
        "attack_type": "system_anomaly",
        "confidence": "Medium",
        "trigger": "Authentication, DNS, unusual traffic, outbound transfer, or high-severity review condition without a stronger rule.",
        "rationale": "The event requires investigation but lacks direct confirmation under these rules.",
    },
    {
        "source": "System/device",
        "rule_id": "SYS-100",
        "label": "benign",
        "attack_type": "none",
        "confidence": "High",
        "trigger": "No higher-priority system/device rule matches.",
        "rationale": "The event fits the current routine-system-event definition.",
    },
]


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _result(
    label: str, attack_type: str, confidence: str, rule_id: str, reason: str
) -> RuleAssessment:
    risk_score = {"benign": 0.05, "suspicious": 0.45, "threat": 0.9}[label]
    return RuleAssessment(label, attack_type, confidence, rule_id, reason, risk_score)


def _patient(event: Mapping[str, Any]) -> RuleAssessment:
    action = _norm(event.get("action") or event.get("access_type"))
    status = _norm(event.get("status"))
    role = _norm(event.get("actor_role") or event.get("accessed_by_role"))
    risky = {"export", "download", "share", "delete"}
    if status == "unauthorized attempt":
        return _result("threat", "unauthorized_access", "High", "PAT-001", "Explicit unauthorized patient-record access attempt.")
    if action == "delete" and status in {"success", "authorized"}:
        return _result("threat", "record_tampering", "High", "PAT-002", "Patient-record deletion succeeded or was authorized.")
    if action in {"export", "download", "share"} and role in {"facilities technician", "hr specialist"} and status in {"success", "authorized"}:
        return _result("threat", "data_exfiltration", "High", "PAT-003", "Non-clinical role completed a high-risk patient-data transfer action.")
    if (action in risky and status == "denied") or action in {"export", "download", "share"}:
        return _result("suspicious", "policy_violation", "Medium", "PAT-010", "Risky patient-data action needs analyst validation.")
    return _result("benign", "none", "High", "PAT-100", "No patient-access threat rule matched.")


def _employee(event: Mapping[str, Any]) -> RuleAssessment:
    action = _norm(event.get("action"))
    status = _norm(event.get("status"))
    role = _norm(event.get("actor_role") or event.get("role"))
    department = _norm(event.get("department"))
    if action == "privilege escalation request" and status == "success":
        return _result("threat", "privilege_escalation", "High", "EMP-001", "Privilege escalation completed successfully.")
    if action == "failed login attempt" and status == "success":
        return _result("threat", "credential_access", "High", "EMP-002", "Failed-login event has an inconsistent successful outcome.")
    if action == "usb device connected" and status == "success" and role not in {"security analyst", "system administrator"}:
        return _result("threat", "removable_media", "High", "EMP-003", "Non-security role successfully connected removable media.")
    if action == "record export" and status == "success" and department not in {"billing", "it security"}:
        return _result("threat", "data_exfiltration", "High", "EMP-004", "Record export succeeded outside expected billing/security functions.")
    risky = {"privilege escalation request", "failed login attempt", "usb device connected", "record export", "vpn connection"}
    if action in risky or status in {"failed", "blocked", "flagged for review"}:
        return _result("suspicious", "account_anomaly", "Medium", "EMP-010", "Risky employee action or review-worthy outcome needs investigation.")
    return _result("benign", "none", "High", "EMP-100", "No employee-activity threat rule matched.")


def _system(event: Mapping[str, Any]) -> RuleAssessment:
    action = _norm(event.get("action") or event.get("event_type"))
    status = _norm(event.get("status"))
    severity = _norm(event.get("severity"))
    if action == "malware signature detected":
        return _result("threat", "malware", "High", "SYS-001", "Malware signature was detected on a hospital system or device.")
    if action == "network port scan":
        return _result("threat", "reconnaissance", "High", "SYS-002", "Network port scanning activity was recorded.")
    if action == "unauthorized access attempt":
        return _result("threat", "unauthorized_access", "High", "SYS-003", "Explicit unauthorized system/device access attempt.")
    if action == "outbound data transfer" and severity in {"high", "critical"} and status == "success":
        return _result("threat", "data_exfiltration", "High", "SYS-004", "High-severity outbound transfer completed successfully.")
    if action == "dns query anomaly" and severity in {"high", "critical"} and status not in {"blocked", "quarantined"}:
        return _result("threat", "command_and_control", "High", "SYS-005", "High-severity DNS anomaly was not contained.")
    suspicious_actions = {"failed authentication", "dns query anomaly", "unusual traffic volume", "outbound data transfer", "system alert"}
    if action in suspicious_actions or (severity in {"high", "critical"} and status in {"failed", "pending review"}):
        return _result("suspicious", "system_anomaly", "Medium", "SYS-010", "System/device anomaly requires analyst review.")
    return _result("benign", "none", "High", "SYS-100", "No system/device threat rule matched.")


def assess_rules(event: Mapping[str, Any]) -> RuleAssessment:
    log_type = _norm(event.get("log_type") or event.get("category"))
    if log_type in {"patient_access", "patient access logs"}:
        return _patient(event)
    if log_type in {"employee_activity", "employee activity logs"}:
        return _employee(event)
    if log_type in {"system_device", "system and device logs"}:
        return _system(event)

    action = _norm(event.get("action"))
    status = _norm(event.get("status"))
    if "unauthorized" in action or status == "unauthorized attempt" or "malware" in action:
        return _result("threat", "generic_security_event", "Medium", "GEN-001", "Generic high-risk security wording matched.")
    if any(term in action for term in ("failed", "scan", "anomaly", "privilege")):
        return _result("suspicious", "generic_anomaly", "Low", "GEN-010", "Generic suspicious behavior matched.")
    return _result("benign", "none", "Low", "GEN-100", "No source-specific rule was available.")
