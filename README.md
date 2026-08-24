# Healthcare Log Threat Model + CTI Fusion

This project evaluates patient-access, employee-activity, and hospital
system/device logs. Each event receives an auditable rule assessment, a
source-specific behavioral-model prediction, relevant live threat-intelligence
evidence, and one final threat decision.

## What is implemented

- Three separate class-balanced random-forest models: one per log stream.
- Three output classes: `benign`, `suspicious`, and `threat`.
- Human-readable labeling rules in `cti/rules.py`.
- A 3,000-row analyst-review sample with 1,000 rows from each source.
- Live routing to OTX/VirusTotal for public IP, domain, URL, and file-hash
  reputation; OSV/NVD for CVE and GHSA vulnerability references.
- A hybrid decision that keeps behavior, rules, IOC intelligence, and
  vulnerability posture separate in the evidence trail.

The source workbooks in `data/raw/` are preserved unchanged. The active
processed dataset contains 30,000 events, 10,000 from each workbook.

## Safety and privacy boundaries

Direct patient, employee, and device identities, names, descriptions,
workstation IDs, raw IP addresses, threat-provider fields, threat references,
rule labels, and analyst labels are not behavioral-model features. IDs are
replaced by one-way local correlation tokens in the processed data.

Only supported public indicators are sent to external intelligence providers.
Private/reserved IP addresses and clinical free text remain local.

## End-to-end workflow

Install dependencies and create the local environment file:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Add available keys to `.env` and never commit it:

```dotenv
OTX_API_KEY=
VIRUSTOTAL_API_KEY=
NVD_API_KEY=
```

Prepare, label, and train:

```powershell
.\.venv\Scripts\python.exe prepare_hospital_data.py
.\.venv\Scripts\python.exe label_hospital_events.py
.\.venv\Scripts\python.exe train_model.py --label-mode synthetic
```

These commands produce:

- `data/processed/hospital_log_events.csv`: normalized operational events.
- `data/processed/hospital_rule_labeled_events.csv`: rule-generated labels.
- `data/processed/analyst_review_sample.csv`: privacy-minimized review sample.
- `threat_model.pkl`: the three trained models and metadata.
- `model_metrics.json`: chronological-holdout metrics and validation warnings.

## Analyst review and human-label retraining

Open the analyst workbook in `outputs/019fbe91-0d15-71b2-a287-a62f3e533db9/`.
Review the three yellow-column sheets, complete the analyst decision fields,
and set completed rows to `Reviewed`. Do not overwrite the synthetic suggestion
columns; they are retained for comparison and auditability.

Then import the completed decisions and retrain:

```powershell
.\.venv\Scripts\python.exe import_analyst_reviews.py
.\.venv\Scripts\python.exe train_model.py `
  --label-mode human `
  --human-labels data/processed/human_reviewed_labels.csv
```

Human-label training deliberately refuses incomplete data. Each source must
contain all three classes and at least 100 reviewed examples per class. For a
production claim, evaluate once more on a later time period that was not used
for labeling or training.

## What the current accuracy means

The current synthetic-rule holdout results are:

| Model | Accuracy | Threat precision | Threat recall | Threat false-positive rate |
| --- | ---: | ---: | ---: | ---: |
| Patient access | 100.00% | 100.00% | 100.00% | 0.00% |
| Employee activity | 99.64% | 95.43% | 100.00% | 0.39% |
| System/device | 99.96% | 100.00% | 100.00% | 0.00% |
| Aggregate | 99.87% | 99.44% | 100.00% | 0.15% |

These numbers measure how consistently the models reproduce the synthetic
rules on the final 25% of events chronologically. They are a software-consistency
check, not a measured real-world hospital threat-detection accuracy. The
real-world accuracy is unknown until independent analysts label the sample and
a future-time test set is evaluated.

The acceptance targets encoded in training are threat recall at least 85%,
threat precision at least 70%, and threat false-positive rate no more than 10%.

## Intelligence routing and decision semantics

| Reference | Databases checked | Authentication |
| --- | --- | --- |
| Public IP, domain, URL, MD5, SHA-1, SHA-256 | AlienVault OTX + VirusTotal | `OTX_API_KEY`, `VIRUSTOTAL_API_KEY` |
| CVE | OSV + NIST NVD | No OSV key; optional `NVD_API_KEY` |
| GHSA advisory | OSV, then NVD for CVE aliases | No OSV key; optional `NVD_API_KEY` |
| Private/reserved/local IP | None; retained locally | Not transmitted |

A malicious IOC can confirm active threat evidence. An OSV/NVD vulnerability
match increases risk and remediation priority, but it is not by itself proof
that the specific log event is an active attack.

Every newly generated incident report contains an explicit row for all four
providers. A row is marked `Queried — available`, `Not applicable`,
`Applicable — not configured`, or `Queried — unavailable`, so the report never
implies that an irrelevant database was checked. Recommended actions are built
from the provider facts and the same log's rule/model context. Each action names
the problem, evidence, and sources. When NVD returns a CISA required action, the
report preserves that action; other response guidance is deterministic local
policy informed by the API evidence, not advice claimed to come directly from
the provider.

Official references: [OSV API](https://google.github.io/osv.dev/api/),
[NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities),
[VirusTotal API v3](https://docs.virustotal.com/reference/overview), and
[AlienVault OTX DirectConnect](https://otx.alienvault.com/api).

## Run

The website now runs as one Flask application: Flask serves the built React
dashboard, loads the official CICIoMT2024 CatBoost artifact once at startup,
and exposes the threat-intelligence endpoints and WebSocket on the same port.

Install the Python and frontend dependencies, then build the dashboard:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Set-Location cti-dashboard
npm install
npm run build
Set-Location ..
```

Start the complete website:

```powershell
.\.venv\Scripts\python.exe flask_app.py
```

Before starting, configure `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `DEV_OTP_CODE`,
and `FLASK_SECRET_KEY` in the untracked `.env` file. Open
`http://127.0.0.1:8000`, sign in with the administrator credentials and
verification code, then use **Run end-to-end test** in the top bar to
run the bundled unseen CICIoT2023 fixture through CatBoost and, in the same
investigation, query AlienVault OTX, VirusTotal, OSV, and NIST NVD. The result
contains the predicted attack family, confidence, provider evidence, fused risk
score, and deterministic response recommendations.

Required deployment files are:

- `flask_app.py` and the `cti/` package.
- `official_ciciomt2024_catboost_12_features_6_classes.joblib`.
- `end_to_end_integration_test_result.json` for the built-in integration test.
- `cti-dashboard/dist/`, generated by `npm run build`.
- `.env`, containing administrator secrets and provider keys. Never publish or
  commit this file.

Main endpoints (all except health and administrator login/session routes require
an authenticated administrator session):

- `POST /api/predict` or `POST /api/analyze`: classify one 12-feature network
  flow and enrich any supported indicators in the same JSON object.
- `POST /api/integration-sample/run`: run the bundled model-plus-four-sources
  integration test.
- `POST /api/intelligence/lookup`: check one IP, domain, URL, hash, CVE, or GHSA.
- `GET /api/intelligence/status`: provider configuration and health without keys.
- `GET /api/model`: training metadata, features, exclusions, and metrics.
- `GET /api/health`: minimal deployment liveness without sensitive metadata.
- `GET /api/database/status`: active SQLite/PostgreSQL backend and stored row counts.
- `GET /api/investigations`: persisted dashboard investigation records.
- `WS /ws/live-logs`: stream classified events to the dashboard.

The authentication cookie is HTTP-only, SameSite Strict, and time limited. Set
`SESSION_COOKIE_SECURE=true` whenever HTTPS is used. The API and WebSocket are
protected by the same server-side session; hiding the dashboard in React alone
is not treated as access control.

Example CatBoost classification and CTI enrichment:

```powershell
$body = @{
  IAT = 83094352.0
  rst_count = 0.0
  Number = 9.5
  'Tot size' = 54.0
  psh_flag_number = 0.0
  Min = 54.0
  Rate = 0.6681432724
  Header_Length = 54.0
  ack_count = 0.0
  'Protocol Type' = 6.0
  'Tot sum' = 567.0
  Max = 54.0
  src_ip = "182.54.217.2"
  cve_id = "CVE-2021-44228"
  asset_criticality = 0.95
} | ConvertTo-Json

Invoke-RestMethod http://127.0.0.1:8000/api/predict `
  -Method Post -ContentType application/json -Body $body
```

## Database modes

No Docker installation is required for the first run. When
`SITE_DATABASE_URL` is not set, the Flask application creates
`data/healthcare_cti.db` and uses SQLite. Each analysis stores the hospital
event, CatBoost prediction, extracted indicators, provider responses, CTI
matches, alert, and alert evidence in the same 25-table schema used by
PostgreSQL.

Check the active database:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/database/status
```

After Docker Desktop is installed, copy the safe example settings into `.env`,
keep the existing API keys, and replace every placeholder password:

```powershell
docker compose up --build -d
docker compose ps
```

The services are:

- Website and Flask API: `http://127.0.0.1:8000`
- PostgreSQL: `127.0.0.1:5432`
- pgAdmin: `http://127.0.0.1:5050`

Inside pgAdmin, register the server with host `db`, port `5432`, database
`healthcare_cti`, username `healthcare_cti`, and the `POSTGRES_PASSWORD` value
from `.env`. PostgreSQL data is kept in the named `postgres_data` volume when
containers stop or restart. Do not run `docker compose down -v` unless the
database is intentionally being deleted.

## PostgreSQL import (optional)

Set `DATABASE_URL`, apply the migration, and import the processed events and
model metadata:

```powershell
.\.venv\Scripts\alembic.exe upgrade head
.\.venv\Scripts\python.exe import_static_data.py
```

Provider responses, extracted references, model predictions, final alerts, and
evidence remain separate in the persistence layer for auditability.

## Supabase PostgreSQL

The Flask backend can use the Supabase Session Pooler without embedding the
database password in a URI. Copy the five settings from
`.env.supabase.example` into `.env`, enter the database password locally, and
remove or comment out `SITE_DATABASE_URL` so it does not keep selecting SQLite.
The configured pooler uses TLS (`sslmode=require`) automatically.

Initialize the remote schema once, then restart Flask:

```powershell
.\.venv\Scripts\alembic.exe upgrade head
```

Never expose `SUPABASE_DB_PASSWORD` or a service-role key to the React client.
Only the Flask backend should connect directly to PostgreSQL.
