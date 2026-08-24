from __future__ import annotations

import asyncio
import hmac
import os
import random
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

import pandas as pd
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from cti.intelligence import ThreatIntelligenceService, classify_indicator
from cti.db.persistence import CTIPersistenceService
from cti.extraction import ExtractedIndicator, extract_indicators
from cti.model import ThreatRiskEngine
from cti.reporting import build_recommended_actions, summarize_provider_evidence


PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")


def load_csv_sample(path: Path, limit: int = 25_000) -> pd.DataFrame:
    try:
        frame = pd.read_csv(path, nrows=limit, low_memory=False)
        print(f"Loaded {path.name}: {len(frame):,} live-stream sample rows")
        return frame
    except Exception as exc:
        print(f"Failed to load {path}: {exc}")
        return pd.DataFrame()


SECURITY_EVENTS_PATH = PROJECT_ROOT / "data" / "processed" / "hospital_log_events.csv"
SECURITY_EVENTS = load_csv_sample(SECURITY_EVENTS_PATH, limit=30_000)
DATASETS = {
    "Patient access logs": SECURITY_EVENTS[
        SECURITY_EVENTS.get("log_type", pd.Series(dtype=str)) == "patient_access"
    ],
    "Employee activity logs": SECURITY_EVENTS[
        SECURITY_EVENTS.get("log_type", pd.Series(dtype=str)) == "employee_activity"
    ],
    "System and device logs": SECURITY_EVENTS[
        SECURITY_EVENTS.get("log_type", pd.Series(dtype=str)) == "system_device"
    ],
}
intelligence = ThreatIntelligenceService(PROJECT_ROOT)
persistence = CTIPersistenceService()
risk_engine = ThreatRiskEngine(PROJECT_ROOT / "threat_model.pkl")
refresh_task: asyncio.Task | None = None


async def posture_refresh_loop() -> None:
    refresh_seconds = max(900, int(os.getenv("INTEL_REFRESH_SECONDS", "21600")))
    while True:
        posture = await intelligence.refresh_posture()
        await asyncio.to_thread(persistence.sync_vulnerability_posture, posture)
        await asyncio.sleep(refresh_seconds)


@asynccontextmanager
async def lifespan(_: FastAPI):
    global refresh_task
    refresh_task = asyncio.create_task(posture_refresh_loop())
    yield
    if refresh_task:
        refresh_task.cancel()
        try:
            await refresh_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="Healthcare CTI Fusion API",
    version="3.0.0",
    description="Hospital log scoring fused with live OSV, NVD, OTX, and VirusTotal evidence.",
    lifespan=lifespan,
)

DEFAULT_ALLOWED_ORIGINS = [
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:5174",
    "http://localhost:5174",
]
allowed_origins = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", ",".join(DEFAULT_ALLOWED_ORIGINS)).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=os.getenv("ALLOWED_ORIGIN_REGEX", r"https?://(localhost|127\.0\.0\.1):\d+"),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@hospital.com").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin12345")
OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", "300"))
DEV_OTP_CODE = os.getenv("DEV_OTP_CODE", "").strip()
otp_store: dict[str, dict[str, Any]] = {}


class LoginRequest(BaseModel):
    email: str
    password: str


class OtpRequest(BaseModel):
    email: str
    code: str


class IndicatorRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=2048)


class PredictionRequest(BaseModel):
    event_time: str | None = Field(default=None, max_length=64)
    log_type: str = Field(default="api_submission", max_length=64)
    location: str = Field(default="unknown", max_length=160)
    department: str = Field(default="unknown", max_length=160)
    actor_role: str = Field(default="unknown", max_length=160)
    action: str = Field(default="unknown", max_length=160)
    object_type: str = Field(default="unknown", max_length=160)
    device_type: str = Field(default="unknown", max_length=160)
    protocol: str = Field(default="unknown", max_length=32)
    severity: str = Field(default="unknown", max_length=32)
    status: str = Field(default="unknown", max_length=64)
    source_port: int = Field(default=0, ge=0, le=65535)
    dest_port: int = Field(default=0, ge=0, le=65535)
    # Legacy network-flow inputs remain accepted for API compatibility.  The
    # new classifier uses the operational-log fields above.
    src_port: int = Field(default=0, ge=0, le=65535)
    dst_port: int = Field(default=0, ge=0, le=65535)
    src_bytes: float = Field(default=0, ge=0)
    dst_bytes: float = Field(default=0, ge=0)
    src_load: float = Field(default=0, ge=0)
    dst_load: float = Field(default=0, ge=0)
    duration: float = Field(default=0, ge=0)
    transactions: float = Field(default=0, ge=0)
    total_packets: float = Field(default=0, ge=0)
    total_bytes: float = Field(default=0, ge=0)
    load: float = Field(default=0, ge=0)
    loss: float = Field(default=0, ge=0)
    packet_loss: float = Field(default=0, ge=0)
    rate: float = Field(default=0, ge=0)
    indicator: str | None = Field(default=None, max_length=2048)
    indicators: list[str] = Field(default_factory=list, max_length=8)
    asset_criticality: float = Field(default=0.5, ge=0, le=1)


class StaticReplayRequest(BaseModel):
    category: str | None = None
    limit: int = Field(default=100, ge=1, le=1_000)


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if pd.isna(value):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    try:
        if pd.isna(value):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def clean_text(value: Any, fallback: str) -> str:
    if value is None or pd.isna(value):
        return fallback
    text = str(value).strip()
    return text if text and text.lower() != "nan" else fallback


def private_indicator_result(candidate: ExtractedIndicator) -> dict[str, Any]:
    """Return auditable local evidence without transmitting private telemetry."""
    return {
        "indicator": candidate.value,
        "type": candidate.indicator_type,
        "field": candidate.field,
        "verdict": "private",
        "confidence": 0.0,
        "sources": {},
        "coverage": {
            "applicable_sources": ["otx", "virustotal"],
            "configured_sources": [], "available_sources": [], "queried_sources": [], "complete": True,
        },
        "message": "Private/local indicator retained locally and not sent to external CTI services.",
        "cached": False,
    }


def choose_primary_enrichment(enrichments: list[dict[str, Any]]) -> dict[str, Any]:
    """Select the most consequential result for the model while retaining all evidence."""
    if not enrichments:
        return {
            "verdict": "no_indicator",
            "confidence": 0.0,
            "sources": {},
            "coverage": {
                "applicable_sources": [],
                "configured_sources": [], "available_sources": [], "queried_sources": [], "complete": True,
            },
            "message": "No supported network or file indicator was present in this static event.",
            "cached": False,
        }
    return max(
        enrichments,
        key=lambda item: (
            item.get("verdict") in {"malicious", "vulnerable"},
            float(item.get("confidence", 0.0) or 0.0),
            bool(item.get("sources")),
        ),
    )


async def assess_static_event(
    event: Mapping[str, Any], *, asset_criticality: float = 0.8
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    """Fuse local telemetry with current external evidence for one static event."""
    candidates = extract_indicators(event)
    public_candidates = [candidate for candidate in candidates if candidate.is_public]
    live_results = await asyncio.gather(
        *(intelligence.enrich_indicator(candidate.value) for candidate in public_candidates),
        return_exceptions=True,
    )
    enrichments: list[dict[str, Any]] = [private_indicator_result(candidate) for candidate in candidates if not candidate.is_public]
    for candidate, result in zip(public_candidates, live_results):
        if isinstance(result, Exception):
            enrichments.append(
                {
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
                        "configured_sources": [], "available_sources": [], "queried_sources": [], "complete": False,
                    },
                    "message": f"Live CTI lookup failed: {str(result)[:200]}",
                    "cached": False,
                }
            )
        else:
            enrichments.append({**result, "field": candidate.field})
    primary = choose_primary_enrichment(enrichments)
    score = risk_engine.score(event, primary, intelligence.posture(), asset_criticality=asset_criticality)
    return score, primary, enrichments


async def build_log_payload(category: str) -> dict[str, Any]:
    dataset = DATASETS.get(category, pd.DataFrame())
    if dataset.empty:
        raise RuntimeError(f"No rows available for {category}")

    sample_row = dataset.sample(n=1).iloc[0].to_dict()
    source_ip = clean_text(sample_row.get("source_ip"), "10.0.0.1")
    destination_target = clean_text(
        sample_row.get("destination_ip"),
        clean_text(sample_row.get("device_type"), clean_text(sample_row.get("object_type"), "local system")),
    )
    score, enrichment, indicator_evidence = await assess_static_event(sample_row, asset_criticality=0.8)
    provider_evidence = summarize_provider_evidence(
        indicator_evidence, intelligence.status()["sources"]
    )
    recommended_actions = build_recommended_actions(
        sample_row, score, enrichment, provider_evidence
    )
    posture_snapshot = {
        key: value for key, value in intelligence.posture().items() if key != "vulnerabilities"
    }
    indicator_value = clean_text(enrichment.get("indicator"), source_ip)
    await asyncio.to_thread(
        persistence.persist_assessment,
        sample_row,
        enrichment,
        score,
        indicator_evidence,
    )

    if score["risk_level"] == "critical":
        tlp = "TLP:RED"
    elif score["risk_level"] == "high":
        tlp = "TLP:AMBER"
    elif score["risk_level"] == "medium":
        tlp = "TLP:GREEN"
    else:
        tlp = "TLP:CLEAR"

    traffic_class = clean_text(sample_row.get("action"), category)
    department = clean_text(
        sample_row.get("department"), clean_text(sample_row.get("location"), "hospital operations")
    )
    now = datetime.now()
    otx_source = (enrichment.get("sources") or {}).get("otx") or {}

    return {
        "log_id": clean_text(
            sample_row.get("event_id"), f"LOG-{now.strftime('%H%M%S')}-{secrets.randbelow(1000):03d}"
        ),
        "category": category,
        "traffic_class": traffic_class,
        "department": department,
        "destination_target": destination_target,
        "source_ip": source_ip,
        "indicator": indicator_value,
        "data_mb": 0,
        "data_unit": "KB",
        "is_threat": score["is_threat"],
        "is_in_otx": int(otx_source.get("pulse_count", 0) or 0) > 0,
        "tlp": tlp,
        "risk_level": score["risk_level"],
        "risk_probability": score["probability"],
        "model_probability": score["base_probability"],
        "intel_verdict": enrichment.get("verdict"),
        "indicator_evidence": indicator_evidence,
        "provider_evidence": provider_evidence,
        "vulnerability_posture": posture_snapshot,
        "recommended_actions": recommended_actions,
        "recommendation_method": (
            "API-informed deterministic response policy. Provider facts are cited per action; "
            "providers do not supply a complete incident-response plan."
        ),
        "risk_reasons": score["reasons"],
        "timestamp": now.strftime("%H:%M:%S"),
        "date": now.strftime("%Y-%m-%d"),
    }


@app.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "datasets": {name: len(dataset) for name, dataset in DATASETS.items()},
        "data_sources": {
            "patient_access": "patient_information_logs.xlsx",
            "employee_activity": "employee_logs.xlsx",
            "system_device": "hospital_system_device_logs.xlsx",
        },
        "model": risk_engine.metadata,
        "intelligence": intelligence.status(),
        "posture": {
            key: value
            for key, value in intelligence.posture().items()
            if key != "vulnerabilities"
        },
    }


@app.get("/api/model")
async def model_info():
    return risk_engine.metadata


@app.get("/api/intelligence/status")
async def intelligence_status():
    return intelligence.status()


@app.post("/api/intelligence/lookup")
async def indicator_lookup(payload: IndicatorRequest):
    try:
        enrichment = await intelligence.enrich_indicator(payload.indicator)
        await asyncio.to_thread(persistence.persist_indicator_lookup, payload.indicator, enrichment)
        return enrichment
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/vulnerabilities/posture")
async def vulnerability_posture():
    return intelligence.posture()


@app.post("/api/vulnerabilities/refresh")
async def vulnerability_refresh():
    posture = await intelligence.refresh_posture()
    await asyncio.to_thread(persistence.sync_vulnerability_posture, posture)
    return posture


@app.post("/api/predict")
async def predict(payload: PredictionRequest):
    event = payload.model_dump(exclude={"indicator", "indicators", "asset_criticality"})
    if not event["source_port"] and event["src_port"]:
        event["source_port"] = event["src_port"]
    if not event["dest_port"] and event["dst_port"]:
        event["dest_port"] = event["dst_port"]
    submitted_indicators = [item for item in [payload.indicator, *payload.indicators] if item]
    try:
        for raw_indicator in submitted_indicators:
            classify_indicator(raw_indicator)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if submitted_indicators:
        event["indicator"] = submitted_indicators[0]
        event["indicators"] = submitted_indicators
    try:
        score, enrichment, indicator_evidence = await assess_static_event(
            event, asset_criticality=payload.asset_criticality
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    for evidence in indicator_evidence:
        if evidence.get("sources"):
            await asyncio.to_thread(persistence.persist_indicator_lookup, evidence["indicator"], evidence)
    provider_evidence = summarize_provider_evidence(
        indicator_evidence, intelligence.status()["sources"]
    )
    recommended_actions = build_recommended_actions(
        event, score, enrichment, provider_evidence
    )
    return {
        **score,
        "indicator_intelligence": enrichment,
        "indicator_evidence": indicator_evidence,
        "provider_evidence": provider_evidence,
        "recommended_actions": recommended_actions,
        "recommendation_method": (
            "API-informed deterministic response policy. Provider facts are cited per action; "
            "providers do not supply a complete incident-response plan."
        ),
        "project_posture": {
            key: value
            for key, value in intelligence.posture().items()
            if key != "vulnerabilities"
        },
    }


@app.post("/api/events/replay")
async def replay_static_events(payload: StaticReplayRequest):
    """Process a bounded static-data batch through the live enrichment pipeline.

    The endpoint is intentionally limited: a production batch worker should
    schedule large replays to respect provider quotas and retain observability.
    """
    categories = [payload.category] if payload.category else list(DATASETS)
    unknown = [name for name in categories if name not in DATASETS]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown category: {unknown[0]}")
    rows: list[dict[str, Any]] = []
    for category in categories:
        rows.extend(DATASETS[category].head(payload.limit).to_dict("records"))
    rows = rows[: payload.limit]
    summary = {"processed": 0, "alerts": 0, "live_lookups": 0, "private_indicators": 0, "failed": 0}
    for event in rows:
        try:
            score, enrichment, evidence = await assess_static_event(event, asset_criticality=0.8)
            await asyncio.to_thread(persistence.persist_assessment, event, enrichment, score, evidence)
            summary["processed"] += 1
            summary["alerts"] += int(score["is_threat"])
            summary["live_lookups"] += sum(1 for item in evidence if item.get("sources"))
            summary["private_indicators"] += sum(1 for item in evidence if item.get("verdict") == "private")
        except Exception:
            summary["failed"] += 1
    return {"mode": "static data with live CTI enrichment", "categories": categories, **summary}


@app.get("/api/alerts")
async def list_alerts(limit: int = 100):
    if not 1 <= limit <= 500:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
    return {"alerts": await asyncio.to_thread(persistence.list_alerts, limit)}


@app.post("/api/admin/login")
async def admin_login(payload: LoginRequest):
    email = payload.email.strip().lower()
    if not (
        hmac.compare_digest(payload.password, ADMIN_PASSWORD)
        and hmac.compare_digest(email, ADMIN_EMAIL)
    ):
        raise HTTPException(status_code=401, detail="Invalid admin credentials.")

    code = DEV_OTP_CODE or f"{secrets.randbelow(1_000_000):06d}"
    otp_store[email] = {"code": code, "expires_at": time.time() + OTP_TTL_SECONDS}
    print(f"Healthcare SOC OTP for {email}: {code}")
    return {"message": "OTP generated.", "expires_in": OTP_TTL_SECONDS}


@app.post("/api/admin/verify-otp")
async def verify_otp(payload: OtpRequest):
    email = payload.email.strip().lower()
    entry = otp_store.get(email)
    if not entry:
        raise HTTPException(status_code=400, detail="No active verification code.")
    if time.time() > entry["expires_at"]:
        otp_store.pop(email, None)
        raise HTTPException(status_code=400, detail="Verification code expired.")
    if not hmac.compare_digest(payload.code.strip(), entry["code"]):
        raise HTTPException(status_code=401, detail="Verification code is not valid.")
    otp_store.pop(email, None)
    return {"message": "Login verified."}


@app.websocket("/ws/live-logs")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    available_categories = [name for name, dataset in DATASETS.items() if not dataset.empty]
    if not available_categories:
        await websocket.close(code=1011, reason="No hospital log datasets loaded.")
        return

    try:
        while True:
            payload = await build_log_payload(random.choice(available_categories))
            await websocket.send_json(payload)
            try:
                # The browser is receive-only. A short receive wait both paces
                # the stream and lets ASGI observe a client disconnect cleanly.
                await asyncio.wait_for(websocket.receive_text(), timeout=1.5)
            except TimeoutError:
                pass
    except WebSocketDisconnect:
        print("Live dashboard disconnected")
