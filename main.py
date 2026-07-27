import asyncio
import hmac
import os
import random
import secrets
import time
from datetime import datetime

import pandas as pd
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Healthcare CTI SOC API")

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

OTX_BLACK_LIST = {
    "10.16.120.72",
    "10.16.120.44",
    "192.168.1.100",
    "malicious-phishing.com",
}

otp_store = {}


class LoginRequest(BaseModel):
    email: str
    password: str


class OtpRequest(BaseModel):
    email: str
    code: str


def load_csv(path):
    try:
        df = pd.read_csv(path, low_memory=False)
        print(f"Loaded {path}: {len(df):,} rows")
        return df
    except Exception as exc:
        print(f"Failed to load {path}: {exc}")
        return pd.DataFrame()


df_attack = load_csv("Attack.csv")
df_env = load_csv("environmentMonitoring.csv")
df_patient = load_csv("patientMonitoring.csv")

DATASETS = {
    "Attack": df_attack,
    "environmentMonitoring": df_env,
    "patientMonitoring": df_patient,
}


def safe_float(value, default=0.0):
    try:
        if pd.isna(value):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value, default=0):
    try:
        if pd.isna(value):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def clean_text(value, fallback):
    if value is None or pd.isna(value):
        return fallback
    text = str(value).strip()
    return text if text and text.lower() != "nan" else fallback


def build_log_payload(category):
    dataset = DATASETS.get(category, pd.DataFrame())

    if dataset.empty:
        raise RuntimeError(f"No rows available for {category}")

    sample_row = dataset.sample(n=1).iloc[0].to_dict()
    source_ip = clean_text(sample_row.get("ip.src"), "10.0.0.1")
    destination_ip = clean_text(sample_row.get("ip.dst"), "10.0.0.2")
    frame_len = safe_float(sample_row.get("frame.len"), 64.0)
    data_kb = round(frame_len / 1024, 2)
    is_threat = safe_int(sample_row.get("label"), 0)
    traffic_class = clean_text(sample_row.get("class"), category)
    is_in_otx = source_ip in OTX_BLACK_LIST or destination_ip in OTX_BLACK_LIST

    if category == "Attack" or traffic_class == "Attack" or is_in_otx:
        tlp = "TLP:RED"
    elif is_threat == 1:
        tlp = "TLP:AMBER"
    elif data_kb > 0.15:
        tlp = "TLP:GREEN"
    else:
        tlp = "TLP:CLEAR"

    mqtt_topic = clean_text(sample_row.get("mqtt.topic"), f"{traffic_class}_Dept")
    now = datetime.now()

    return {
        "log_id": f"LOG-{now.strftime('%H%M%S')}-{secrets.randbelow(1000):03d}",
        "category": category,
        "traffic_class": traffic_class,
        "department": mqtt_topic,
        "destination_target": destination_ip,
        "source_ip": source_ip,
        "data_mb": data_kb,
        "data_unit": "KB",
        "is_threat": is_threat,
        "is_in_otx": is_in_otx,
        "tlp": tlp,
        "timestamp": now.strftime("%H:%M:%S"),
        "date": now.strftime("%Y-%m-%d"),
    }


@app.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "datasets": {name: len(dataset) for name, dataset in DATASETS.items()},
    }


@app.post("/api/admin/login")
async def admin_login(payload: LoginRequest):
    email = payload.email.strip().lower()
    password_matches = hmac.compare_digest(payload.password, ADMIN_PASSWORD)
    email_matches = hmac.compare_digest(email, ADMIN_EMAIL)

    if not email_matches or not password_matches:
        raise HTTPException(status_code=401, detail="Invalid admin credentials.")

    code = DEV_OTP_CODE or f"{secrets.randbelow(1_000_000):06d}"
    otp_store[email] = {
        "code": code,
        "expires_at": time.time() + OTP_TTL_SECONDS,
    }

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
        await websocket.close(code=1011, reason="No telemetry datasets loaded.")
        return

    try:
        while True:
            payload = build_log_payload(random.choice(available_categories))
            await websocket.send_json(payload)
            await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        print("Live dashboard disconnected")
