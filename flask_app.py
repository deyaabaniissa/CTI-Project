from __future__ import annotations

import asyncio
import hmac
import json
import os
import random
import secrets
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

from cti.catboost_ids import CatBoostIDSService
from cti.db.site_persistence import SitePersistenceService
from cti.extraction import extract_indicators
from cti.intelligence import ThreatIntelligenceService
from cti.reporting import summarize_provider_evidence


PROJECT_ROOT = Path(__file__).resolve().parent
DIST_DIR = PROJECT_ROOT / "cti-dashboard" / "dist"
MODEL_PATH = PROJECT_ROOT / "official_ciciomt2024_catboost_12_features_6_classes.joblib"
SAMPLE_PATH = PROJECT_ROOT / "data" / "demo" / "integration_sample.json"
OFFICIAL_TEST_REPLAY_PATH = (
    PROJECT_ROOT
    / "data"
    / "evaluation"
    / "official_test_50_samples_per_family_full_results.json"
)
RESULTS_PATH = PROJECT_ROOT / "outputs" / "flask_investigations.jsonl"

load_dotenv(PROJECT_ROOT / ".env")
RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)


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
            "event": dict(event),
            "cti_summary": list(result.get("cti_summary") or []),
            "observables": dict(result.get("observables") or {}),
            "risk_score": float(result.get("risk_score") or 0.0),
            "risk_level": str(result.get("risk_level") or "low"),
            "recommended_action_texts": [str(value) for value in result.get("recommended_actions") or []],
            "source_investigation_id": str(result.get("investigation_id") or ""),
            "source_created_at": str(result.get("created_at") or ""),
        })
    return tuple(rows)


def evaluation_recommendations(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    risk_level = str(row.get("risk_level") or "low")
    priority = "Critical" if risk_level == "critical" else "High" if risk_level == "high" else "Review"
    sources = sorted({str(item.get("source")) for item in row.get("cti_summary", []) if item.get("source")})
    return [
        {
            "priority": priority,
            "action": action,
            "problem": f"Four-source integration result for a {row['predicted_family']} prediction.",
            "evidence_sources": sources,
            "evidence": "Recommendation returned by the saved four-source investigation.",
        }
        for action in row.get("recommended_action_texts", [])
    ]


def evaluation_provider_evidence(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    provider_metadata = {
        "OTX": ("otx", "AlienVault OTX"),
        "VirusTotal": ("virustotal", "VirusTotal"),
        "OSV": ("osv", "OSV"),
        "NVD": ("nvd", "NIST NVD"),
    }
    grouped: dict[str, list[dict[str, Any]]] = {name: [] for name in provider_metadata}
    for raw in row.get("cti_summary", []):
        source = str(raw.get("source") or "")
        if source in grouped:
            grouped[source].append(dict(raw))

    evidence: list[dict[str, Any]] = []
    for source, (provider_id, provider_name) in provider_metadata.items():
        observations = grouped[source]
        available = bool(observations) and all(bool(item.get("ok")) for item in observations)
        modes = sorted({str(item.get("lookup_mode") or "unknown") for item in observations})
        query_values = [str(item.get("query_value") or "") for item in observations]
        evidence.append({
            "provider_id": provider_id,
            "provider": provider_name,
            "configured": True,
            "applicable": True,
            "queried": bool(observations),
            "available": available,
            "status": "available" if available else "unavailable",
            "result": (
                f"{len(observations)} saved lookup(s) via {', '.join(modes)}: "
                + "; ".join(query_values)
                if observations
                else "No saved result for this provider."
            ),
            "observations": observations,
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
    tlp = "TLP:RED" if risk_level in {"critical", "high"} else "TLP:AMBER" if risk_level == "medium" else "TLP:GREEN"
    return {
        "log_id": row["sample_id"],
        "investigation_id": row["sample_id"],
        "date": "Official TEST",
        "timestamp": "Replay",
        "category": "IoMT network flows",
        "traffic_class": predicted_family,
        "true_family": row["true_family"],
        "prediction_correct": bool(row["correct"]),
        "attack_subclass": row["attack_subclass"],
        "department": "CICIoMT2024 model evaluation",
        "source_ip": str(event.get("src_ip") or "Not supplied"),
        "destination_target": str(event.get("asset_id") or event.get("product") or row["source_file"]),
        "source_dataset": row["source_dataset"],
        "source_split": row["source_split"],
        "source_row_number": row["source_row_number"],
        "data_mb": 0.0,
        "data_unit": "KB",
        "is_threat": int(predicted_family != "Benign"),
        "is_in_otx": is_in_otx,
        "risk_level": risk_level,
        "risk_probability": round(risk_score / 100.0, 6),
        "risk_score": round(risk_score, 2),
        "model_probability": round(confidence, 6),
        "intel_verdict": "four-source evidence returned",
        "tlp": tlp,
        "evaluation_mode": True,
        "features": row["features"],
        "class_probabilities": row["probabilities"],
        "provider_evidence": evaluation_provider_evidence(row),
        "indicator_evidence": cti_summary,
        "recommended_actions": evaluation_recommendations(row),
        "recommendation_method": "Saved recommendations from the CatBoost plus four-source integration run.",
        "risk_reasons": [
            f"Ground truth: {row['true_family']}.",
            f"CatBoost prediction: {predicted_family} ({confidence:.1%}).",
            "Correct prediction." if row["correct"] else "Incorrect prediction retained for transparent evaluation.",
            f"Four-source risk score: {risk_score:.2f}/100 ({risk_level}).",
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


async def enrich_event(event: Mapping[str, Any]) -> list[dict[str, Any]]:
    candidates = extract_indicators(event)
    public = [candidate for candidate in candidates if candidate.is_public]
    results = await asyncio.gather(
        *(intelligence.enrich_indicator(candidate.value) for candidate in public),
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

    model_attack_score = (
        prediction["confidence"]
        if prediction["predicted_family"] != "Benign"
        else 1.0 - prediction["confidence"]
    )
    cti_score = max(
        (
            float(item.get("confidence", 0.0) or 0.0)
            for item in evidence
            if item.get("verdict") in {"malicious", "vulnerable"}
        ),
        default=0.0,
    )
    asset_criticality = min(max(float(event.get("asset_criticality", 0.8)), 0.0), 1.0)
    risk_score = round(100 * (0.45 * model_attack_score + 0.40 * cti_score + 0.15 * asset_criticality), 2)
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
    log = {
        "log_id": f"AI-{now.strftime('%H%M%S')}-{random.randint(100, 999)}",
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
        "is_in_otx": bool(result["source_coverage"].get("otx", {}).get("available")),
        "risk_level": result["risk_level"],
        "risk_probability": result["risk_score"] / 100.0,
        "model_probability": prediction["confidence"],
        "intel_verdict": "malicious" if result["is_threat"] else "unknown",
        "tlp": "TLP:RED" if result["risk_level"] == "critical" else "TLP:AMBER" if result["risk_level"] == "high" else "TLP:GREEN",
        "provider_evidence": result["provider_evidence"],
        "indicator_evidence": result["indicator_evidence"],
        "recommended_actions": result["recommended_actions"],
        "risk_reasons": [
            f"CatBoost prediction: {prediction['predicted_family']} ({prediction['confidence']:.1%}).",
            f"Combined model, CTI, and asset risk: {result['risk_score']:.1f}/100.",
        ],
        "model_details": prediction,
        "investigation_id": result["investigation_id"],
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


app = Flask(__name__, static_folder=str(DIST_DIR), static_url_path="")
app.config["JSON_SORT_KEYS"] = False

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


@app.get("/api/intelligence/status")
def intelligence_status() -> Any:
    return jsonify(intelligence.status())


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
