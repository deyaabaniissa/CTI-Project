# Healthcare IoMT Cyber Threat Intelligence SOC

This repository contains a secured IoMT network-intrusion investigation platform. A trained CatBoost classifier analyzes network-flow features, supported public indicators are enriched through four live threat-intelligence providers, and the complete evidence trail is stored for analyst review.

## Model scope

The deployed detector is **machine learning, not deep learning**.

- Algorithm: two CatBoost gradient-boosting models in sequence — a Benign-vs-Attack gate, then an attack-family classifier run only when stage 1 says "Attack". A flat 6-way classifier has to draw the rare-family boundary against the full mass of Benign traffic, which starves precision on the rarest family; splitting the decision removes Benign from competing for that boundary entirely.
- Training dataset: the public Kaggle mirror of the official CICIoMT2024 WiFI_and_MQTT split (`limamateus/cic-iomt-2024-wifi-mqtt`), downloaded automatically by `training/train_catboost_model.py`.
- Input: 12 numeric network-flow features.
- Output classes: `Benign`, `DDoS`, `DoS`, `MQTT`, `Recon`, and `Spoofing`.
- Zero-row cleaning: a row is removed only when all 12 selected features are zero or missing.
- Balancing: stage 1 matches all Benign rows against an equal-sized, evenly-split attack sample. Stage 2 gives DDoS/DoS 300,000 real rows each (they have millions available) and caps the other three families at 30,000, oversampling Spoofing (only ~16K rows exist) up to that mark.

The 12 required features are:

```text
IAT, rst_count, Number, Tot size, psh_flag_number, Min,
Rate, Header_Length, ack_count, Protocol Type, Tot sum, Max
```

The deployed artifact is:

```text
model/ciciomt2024_catboost_12_features_6_classes.joblib
```

To retrain from scratch:

```text
python training/train_catboost_model.py
```

This downloads the dataset into `data/raw/ciciomt2024/` (gitignored, ~2GB) on first run, trains, evaluates against the full untouched official TEST split, and writes the artifact to `model/`.

## Evaluation

### In-domain official CICIoMT2024 test

The scientific evaluation uses all **1,614,182 untouched Official TEST rows** (the entire official TEST split, not a reduced sample). The TEST split is never used for training, class balancing, feature selection, or tuning.

| Metric | Score |
| --- | ---: |
| Accuracy | 95.03% |
| Balanced accuracy | 93.57% |
| Macro F1 | 90.39% |
| Weighted F1 | 94.88% |

Per-family precision/recall on the full TEST split:

| Family | Precision | Recall | F1 | Support |
| --- | ---: | ---: | ---: | ---: |
| Benign | 96.09% | 97.30% | 96.69% | 37,607 |
| DDoS | 93.30% | 99.95% | 96.51% | 1,066,764 |
| DoS | 99.90% | 81.59% | 89.82% | 416,676 |
| MQTT | 99.92% | 98.65% | 99.28% | 63,715 |
| Recon | 99.59% | 96.55% | 98.05% | 27,676 |
| Spoofing | 48.03% | 87.39% | 61.99% | 1,744 |

**Known ceiling — DoS/DDoS confusion.** 18% of DoS traffic gets labeled DDoS. Confirmed via Cohen's d across all 46 raw dataset columns that no available feature meaningfully separates the two (best is `Variance` at d=0.32 — a small effect): these are per-flow aggregates and don't encode source-IP cardinality, the actual distinguishing property of a *distributed* attack. Also confirmed it isn't a sampling artifact — giving both classes 10x more real training rows left the misclassification count essentially unchanged while it measurably improved every other family. Operationally lower-severity than it looks: both remain correctly flagged as attack traffic, so it's a within-attack label swap, not a missed detection.

**Prior single-stage model, for comparison** (flat 6-way classifier, same features/data): accuracy 99.64%, balanced accuracy 95.64%, macro F1 89.08%, DoS F1 99.89%, but Spoofing F1 only 42.78% (28% precision — roughly 3,000 Benign/MQTT/Recon rows misclassified as Spoofing per 1.6M-row window, since a flat classifier has to draw Spoofing's boundary against the full mass of Benign traffic). The two-stage architecture trades some DoS/DDoS purity for materially better rare-attack detection, which matters more for a SOC tool: Spoofing is a stealthy on-path attack worth catching reliably, whereas DoS/DDoS are loud floods that get the same "attack, high risk" response either way.

Retraining is fully reproducible: `python training/train_catboost_model.py`.

### Website evaluation replay

`data/evaluation/official_test_50_samples_per_family_results.csv` / `_full_results.json` hold a saved 300-row replay (50 per family). The website uses only the 12 numeric flow features and saved CatBoost predictions from those rows. CICIoMT2024 does not provide an attributable IP/domain/hash, CVE, or package for each exported flow, so its evaluation reports do not query CTI providers. OTX and VirusTotal are queried for real IoCs, while OSV and NVD are queried for real CVE/vulnerability references submitted through a live event or the clearly labeled integration fixture. This prevents one demonstration indicator from being misrepresented as evidence for every evaluation row.

**Risk separation.** Evaluation-row risk is derived from the model prediction only. Live-event risk uses the documented model/CTI/asset fusion after the event's own indicators are enriched. This prevents unrelated demonstration evidence from changing an Official TEST prediction.

| Metric | Score |
| --- | ---: |
| Rows | 300 |
| Correct predictions | 278 |
| Replay accuracy | 92.67% |

Per-family (50 samples each): Benign 41/50, DDoS 50/50, DoS 50/50, MQTT 49/50, Recon 47/50, and Spoofing 41/50. This balanced replay is a compact, reproducible demonstration sample; the untouched full official test split remains the primary model evaluation.

The replay powers the website's searchable TEST table and per-row PDF reports. It also enters the visible traffic log without creating duplicate incident rows. It does not replace the full-scale scientific evaluation above. Each report uses the exact saved prediction, confidence, 12 feature values, and six class probabilities. CTI rows are explicitly marked not applicable because the exported evaluation rows contain no attributable indicators.

## Investigation workflow

```text
IoMT network-flow event
        |
        v
12-feature validation
        |
        v
CatBoost machine-learning classification
        |
        +--> OTX and VirusTotal for public IP/domain/URL/hash evidence
        |
        +--> OSV and NVD for package/CVE/GHSA evidence
        |
        v
Policy-based risk fusion and evidence-linked response actions
        |
        v
PostgreSQL/Supabase or local SQLite persistence
```

The four providers are routed by indicator type; an irrelevant source is not described as queried. The combined score is a policy-based risk score, not a calibrated probability. Response recommendations are deterministic and evidence-linked, not generated by a deep-learning or language model.

## Implemented platform components

- Flask API and authenticated WebSocket stream.
- React security-operations interface.
- CatBoost model loaded once at application startup.
- Live AlienVault OTX, VirusTotal, OSV, and NIST NVD enrichment.
- SQLite for local use or PostgreSQL/Supabase for persistent storage.
- Stored network-flow events, predictions, indicators, provider responses, matches, alerts, and evidence.
- A dedicated `model_evaluation_samples` table containing the 300 held-out replay rows; these records never enter the live event or alert tables.
- Printable incident reports and model/EDA panels.
- A clearly labeled end-to-end integration fixture that exercises CatBoost and all applicable CTI routes.

The WebSocket streams newly persisted investigations. It does not capture packets directly from a network interface. Production packet ingestion would require a flow extractor that produces the same 12-feature schema before calling the API.

## PCAP role and CTI extraction

The official CSV feature tables were already produced from the original PCAP captures. CatBoost is therefore trained on the 12 numeric flow features, not on raw packet bytes. Re-training directly on PCAP would first require reproducing the dataset's complete flow-extraction window and aggregation logic; feeding packets directly to CatBoost would change the schema and invalidate the saved evaluation.

PCAP remains valuable as the evidence plane. The project now includes a streaming extractor that keeps indicators attributable to their capture and flow:

```powershell
.\.venv\Scripts\python.exe extract_pcap_indicators.py `
  "CIC dataset\WiFi_and_MQTT\attacks\PCAP\test\ARP_Spoofing_test.pcap" `
  --output data\pcap\arp_spoofing_indicators.json
```

The JSON separates:

- all observed local/public IPs, DNS domains, and clear-text HTTP URLs;
- `api_ready_indicators`, which contains only public IoCs suitable for OTX/VirusTotal;
- per-flow provenance so an indicator is never copied onto unrelated evaluation rows;
- routing guidance explaining that NVD/OSV require a CVE or package/version from an asset inventory rather than a numeric flow feature.

Private RFC1918 addresses remain in the local audit record but are never sent to external providers. TLS-encrypted hostnames may not be visible unless the capture exposes DNS or other unencrypted metadata.

The authenticated dashboard now includes a **PCAP Investigation** workspace. An analyst can upload a `.pcap`/`.pcapng` file or choose one of six local CICIoMT2024 test captures. Flask extracts packet evidence, queries at most 10 public IoCs by default, keeps OSV/NVD limited to explicitly supplied CVEs, calculates an evidence score, generates response recommendations, and stores the complete report in the `pcap_investigations` table. CatBoost runs only when the analyst also supplies a valid JSON object containing all 12 model features; otherwise the report explicitly records `model: not_run`.

## Install and run locally

Install Python and frontend dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Set-Location cti-dashboard
npm install
npm run build
Set-Location ..
```

Copy `.env.example` to `.env`, then configure administrator credentials, a six-digit development verification code, a strong Flask secret, and any available CTI API keys. Never commit `.env`.

For an entirely local database, keep:

```dotenv
SITE_DATABASE_URL=sqlite:///data/healthcare_cti.db
```

For a local PostgreSQL server, set `SITE_DATABASE_URL` to its SQLAlchemy PostgreSQL URL. For Supabase, keep `SUPABASE_DB_HOST`, `SUPABASE_DB_PORT`, `SUPABASE_DB_NAME`, `SUPABASE_DB_USER`, and `SUPABASE_DB_PASSWORD` server-side. Supabase is managed PostgreSQL; the same application schema and the 300-row replay work in either mode.

Start the platform:

```powershell
.\.venv\Scripts\python.exe flask_app.py
```

Open `http://127.0.0.1:8000` and sign in with the locally configured administrator credentials.

## Main API routes

All routes except health and administrator authentication require an authenticated session.

- `POST /api/predict` or `POST /api/analyze`: classify one 12-feature flow and enrich supported indicators in the same event.
- `POST /api/integration-sample/run`: execute the labeled model-plus-CTI integration fixture.
- `GET /api/pcap/samples`: list the six curated local class captures available to the PCAP workspace.
- `POST /api/pcap/analyze`: upload/select a capture, extract attributable evidence, run applicable live CTI queries, and persist the report.
- `GET /api/pcap/investigations`: return stored PCAP investigation reports from SQLite/PostgreSQL/Supabase.
- `POST /api/intelligence/lookup`: query one supported public indicator.
- `GET /api/intelligence/status`: report provider configuration and availability without exposing keys.
- `GET /api/model`: return CatBoost type, features, classes, metrics, balance audit, and feature importance.
- `GET /api/evaluation-samples`: return the 300 unique Official TEST predictions and their per-row report data.
- `GET /api/database/status`: return the selected database backend and persisted row counts.
- `GET /api/investigations`: return stored dashboard investigations.
- `WS /ws/live-logs`: stream newly stored investigations.

## Example analysis request

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
  src_ip = '182.54.217.2'
  cve_id = 'CVE-2021-44228'
  asset_criticality = 0.95
} | ConvertTo-Json

Invoke-RestMethod http://127.0.0.1:8000/api/predict `
  -Method Post -ContentType application/json -Body $body
```

## Database modes

SQLite requires no Docker or remote service. PostgreSQL can be run with `compose.yaml`, while Supabase can be configured using the separate `SUPABASE_DB_*` environment variables. Database passwords and service-role credentials must remain server-side.

Apply schema migrations with:

```powershell
.\.venv\Scripts\alembic.exe upgrade head
```

## Verification

Run the Python test suite:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Build the production frontend:

```powershell
Set-Location cti-dashboard
npm run build
```

## Security and scientific boundaries

- Only supported public indicators are sent to external CTI providers; private and reserved IP addresses remain local.
- The API and WebSocket are protected by the same server-side administrator session.
- Authentication cookies are HTTP-only and SameSite Strict. Enable `SESSION_COOKIE_SECURE=true` when HTTPS is used.
- The CICIoMT2024 score measures in-domain performance. It is not claimed as universal hospital-network accuracy.
- The current platform is an IoMT security prototype and does not contain manufactured patient, employee, or hospital-operations training data.
- CatBoost is a machine-learning gradient-boosting model; it is not a deep-learning model.
