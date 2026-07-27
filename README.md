# Healthcare CTI SOC Project

This project combines a FastAPI telemetry backend with a React SOC dashboard for monitoring healthcare network traffic.

## What It Does

- Streams live log samples from attack, environment, and patient monitoring datasets.
- Classifies events with TLP labels.
- Supports OTP-protected admin access for the dashboard.
- Shows live metrics, threat trends, TLP distribution, filtering, CSV export, and printable incident reports.
- Includes helper scripts for OTX IoC collection, simulated hospital logs, and model training.

## Backend

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Optional environment settings are documented in `.env.example`.

Start the API:

```bash
uvicorn main:app --host 127.0.0.1 --port 8000
```

Default local admin credentials are `admin@hospital.com` and `admin12345`. Change them with `ADMIN_EMAIL` and `ADMIN_PASSWORD` before using the project outside local development.

For a local demo where the backend runs hidden, you can set `DEV_OTP_CODE=123456` before starting the API.

## Frontend

```bash
cd cti-dashboard
npm install
npm run dev
```

The frontend connects to the backend at `http://127.0.0.1:8000` by default.
