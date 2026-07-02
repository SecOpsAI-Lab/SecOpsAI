# SecOpsAI — Production Detection API

**Member 5 — Backend & API Engineer**

FastAPI-based production API wrapping the adversarial-hardened XGBoost detection model. Security controls built in by design: per-sensor API key auth, rate limiting, input validation, structured audit logging, and label-only output (ADR-004).

---

## Table of Contents

- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Running the API](#running-the-api)
- [API Endpoints](#api-endpoints)
- [Authentication](#authentication)
- [Security Controls](#security-controls)
- [Integration Points](#integration-points)
- [Testing](#testing)
- [Docker](#docker)
- [Environment Variables](#environment-variables)
- [Handoff to Member 6](#handoff-to-member-6)

---

## Project Structure

```
api/
├── main.py              # FastAPI app — /health, POST /detect, /metrics
├── models.py            # Pydantic schemas (37 UNSW-NB15 features)
├── auth.py              # X-API-Key authentication
├── rate_limiter.py      # Sliding window rate limiter (100 RPM)
├── audit.py             # Structured JSON audit logging
├── inference.py         # Model & scaler loading, prediction
├── db.py                # Async PostgreSQL (detections + audit_log)
├── config.py            # Settings (model paths, Postgres, rate limit)
├── Dockerfile           # Hardened container (non-root, UID 1000)
├── docker-compose.yml   # Override — adds API to existing stack
├── requirements.txt     # Python dependencies
├── README.md            # This file
└── tests/
    ├── __init__.py
    └── test_api.py      # 12 integration tests (91% coverage)
```

---

## Quick Start

```bash
# Requires Python 3.11–3.13 (3.14+ not yet supported by all wheels)

# 1. Install dependencies
pip install -r api/requirements.txt

# 2. Run the API
uvicorn api.main:app --reload --port 8000

# 3. Smoke test
curl http://localhost:8000/health
curl -X POST http://localhost:8000/detect \
  -H "X-API-Key: dev-sensor-001" \
  -H "Content-Type: application/json" \
  -d '{"dur": 100.0, "rate": 50.0, "sload": 10000.0, "dload": 5000.0, "spkts": 10, "dpkts": 5, "sbytes": 500.0, "dbytes": 200.0, "sloss": 0, "dloss": 0, "sinpkt": 50.0, "dinpkt": 30.0, "sjit": 10.0, "djit": 5.0, "swin": 255, "dwin": 255, "tcprtt": 10.0, "synack": 5.0, "ackdat": 3.0, "smean": 100.0, "dmean": 80.0, "trans_depth": 1, "response_body_len": 500.0, "ct_src_dport_ltm": 1, "ct_dst_sport_ltm": 1, "is_ftp_login": 0, "ct_ftp_cmd": 0, "ct_flw_http_mthd": 0, "is_sm_ips_ports": 0, "proto_enc": 6, "service_enc": 0, "state_enc": 2, "byte_ratio": 1.5, "pkt_ratio": 1.2, "total_bytes": 700.0, "jit_ratio": 2.0, "dur_bin_enc": 2}'
```

---

## Running the API

### Local development

```bash
uvicorn api.main:app --reload --port 8000
```

### Docker (standalone)

```bash
docker build -f api/Dockerfile -t secopsai-api .
docker run -p 8000:8000 \
  -e ALLOWED_API_KEYS=dev-sensor-001,dev-sensor-002 \
  secopsai-api
```

### Docker (with existing stack — Postgres + MLflow)

```bash
docker compose -f docker-compose.yml -f api/docker-compose.yml up
```

---

## API Endpoints

### `GET /health`

Health check for load balancers and Kubernetes probes.

**Response 200:**
```json
{
  "status": "ok",
  "model_loaded": true,
  "scaler_loaded": true
}
```

### `POST /detect`

Main detection endpoint. Accepts 37 UNSW-NB15 network flow features, returns a label-only verdict.

**Headers:**
| Header | Required | Description |
|--------|----------|-------------|
| `X-API-Key` | Yes | Per-sensor API key |
| `Content-Type` | Yes | `application/json` |

**Request body** — 37 features:

| Field | Type | Bounds | Description |
|-------|------|--------|-------------|
| `dur` | float | 0 – 1e9 | Flow duration |
| `rate` | float | 0 – 1e9 | Packets per second |
| `sload` | float | 0 – 1e9 | Source load (bytes/sec) |
| `dload` | float | 0 – 1e9 | Destination load |
| `spkts` | int | 0 – 1e7 | Source packets |
| `dpkts` | int | 0 – 1e7 | Destination packets |
| `sbytes` | float | 0 – 1e9 | Source bytes |
| `dbytes` | float | 0 – 1e9 | Destination bytes |
| `sloss` | int | 0 – 1e7 | Source packet loss |
| `dloss` | int | 0 – 1e7 | Destination packet loss |
| `sinpkt` | float | 0 – 1e9 | Source inter-packet arrival |
| `dinpkt` | float | 0 – 1e9 | Destination inter-packet arrival |
| `sjit` | float | 0 – 1e9 | Source jitter |
| `djit` | float | 0 – 1e9 | Destination jitter |
| `swin` | int | 0 – 65535 | Source TCP window |
| `dwin` | int | 0 – 65535 | Destination TCP window |
| `tcprtt` | float | 0 – 1e9 | TCP RTT |
| `synack` | float | 0 – 1e9 | SYN-ACK time |
| `ackdat` | float | 0 – 1e9 | ACK data time |
| `smean` | float | 0 – 1e5 | Mean source packet size |
| `dmean` | float | 0 – 1e5 | Mean destination packet size |
| `trans_depth` | int | 0 – 100 | Transaction depth |
| `response_body_len` | float | 0 – 1e9 | Response body length |
| `ct_src_dport_ltm` | int | 0 – 1e5 | Count src-dport last time |
| `ct_dst_sport_ltm` | int | 0 – 1e5 | Count dst-sport last time |
| `is_ftp_login` | int | 0 – 1 | FTP login flag |
| `ct_ftp_cmd` | int | 0 – 100 | FTP command count |
| `ct_flw_http_mthd` | int | 0 – 100 | HTTP method count |
| `is_sm_ips_ports` | int | 0 – 1 | Same IP/port flag |
| `proto_enc` | int | 0 – 255 | Encoded protocol |
| `service_enc` | int | 0 – 255 | Encoded service |
| `state_enc` | int | 0 – 255 | Encoded state |
| `byte_ratio` | float | 0 – 1e9 | Byte ratio |
| `pkt_ratio` | float | 0 – 1e9 | Packet ratio |
| `total_bytes` | float | 0 – 1e9 | Total bytes |
| `jit_ratio` | float | 0 – 1e9 | Jitter ratio |
| `dur_bin_enc` | int | 0 – 10 | Duration bin encoded |

**Response 200:**
```json
{
  "request_id": "1164e4c8-5881-4f3f-bc35-1c82621688bc",
  "verdict": "BENIGN",
  "latency_ms": 2.063
}
```

**Response 403** (missing API key):
```json
{ "detail": "Missing API key header" }
```

**Response 401** (invalid/revoked API key):
```json
{ "detail": "Invalid or revoked API key" }
```

**Response 422** (validation error — NaN, Inf, out-of-range):
```json
{ "detail": "NaN/Inf values are not allowed" }
```

**Response 429** (rate limit exceeded):
```json
{ "detail": "Rate limit exceeded" }
```
Headers: `Retry-After: 45`

### `GET /metrics/`

Prometheus metrics for Grafana dashboards. Requires trailing slash.

**Metrics exposed:**
- `secopsai_requests_total{endpoint, method}` — Request counter
- `secopsai_detections_total{verdict}` — Detection verdict counter
- `secopsai_inference_seconds` — Inference latency histogram

---

## Authentication

Per-sensor API key validation via the `X-API-Key` header.

| Scenario | Status | Detail |
|----------|--------|--------|
| Missing header | 403 | `Missing API key header` |
| Unrecognized key | 401 | `Invalid or revoked API key` |
| Valid key | 200 | Detection processed |

Default keys: `dev-sensor-001`, `dev-sensor-002` (configurable via `ALLOWED_API_KEYS` environment variable).

---

## Security Controls

| Threat Model ID | Control | Implementation |
|-----------------|---------|----------------|
| TM-001 (Spoofing) | Per-sensor API key auth | `api/auth.py` |
| TM-005 (DoS) | Rate limiting (100 RPM) | `api/rate_limiter.py` |
| TM-004 (Info disclosure) | Structured errors, no stack traces | `api/main.py` exception handlers |
| TM-006 (Container escape) | Non-root user, UID 1000 | `api/Dockerfile` |
| TM-009 (Model inversion) | Label-only output, no probabilities | `api/inference.py` + `api/models.py` |
| T5 / R1 (Audit tampering) | SHA-256 checksummed audit logs | `api/db.py` |
| ADR-003 | Non-root containers | Dockerfile — `USER secops` |
| ADR-004 | Label-only ML output | Response model excludes probability |

---

## Integration Points

### Member 2 — Data Engineer

The API requires the **StandardScaler** fitted by Member 2's data pipeline to scale raw UNSW-NB15 features before inference. Coordinate with Member 2 to add the following to their pipeline:

```python
import joblib
joblib.dump(scaler, "models/scaler.pkl")
```

The scaler file should be placed at the path specified by the `SCALER_PATH` environment variable (default: `models/scaler.pkl`).

### Member 3 — ML Engineer

The API loads Member 3's XGBoost model from `models/ml/xgboost_detector.pkl` (configurable via `MODEL_PATH`). Once Member 4 delivers the adversarial-hardened version, update the path to `models/xgboost_hardened.pkl`.

### Member 4 — Red Team

After adversarial hardening of the model, provide the hardened `.pkl` file at a known path and update the `MODEL_PATH` environment variable accordingly.

### Member 6 — SecOps Engineer

See [Handoff to Member 6](#handoff-to-member-6) below.

---

## Testing

### Run tests

```bash
pytest api/tests/ -v

# With coverage (requires ≥80%)
pytest api/tests/ -v --cov=api --cov-report=term-missing --cov-fail-under=80
```

### Test suite (12 tests)

| Test | What it verifies |
|------|------------------|
| `test_health` | `/health` returns 200 with model/scaler status |
| `test_detect_no_api_key` | Missing key returns 403 |
| `test_detect_invalid_api_key` | Bad key returns 401 |
| `test_detect_valid` | Valid request returns 200 with correct response shape |
| `test_detect_nan_rejected` | NaN values return 422 |
| `test_detect_inf_rejected` | Infinity values return 422 |
| `test_detect_out_of_range_rejected` | Negative float returns 422 |
| `test_detect_negative_int_rejected` | Negative int returns 422 |
| `test_rate_limit_429` | >100 RPM per key returns 429 with Retry-After |
| `test_latency_under_200ms` | Response latency under 200ms |
| `test_metrics_endpoint` | `/metrics/` exposes Prometheus counters |
| `test_request_id_header` | Response includes `X-Request-ID` header |

---

## Docker

### Build

```bash
docker build -f api/Dockerfile -t secopsai-api .
```

### Run

```bash
docker run -p 8000:8000 \
  -e ALLOWED_API_KEYS=dev-sensor-001,dev-sensor-002 \
  -e POSTGRES_HOST=host.docker.internal \
  secopsai-api
```

### Compose override (with existing stack)

```bash
docker compose -f docker-compose.yml -f api/docker-compose.yml up
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ALLOWED_API_KEYS` | `dev-sensor-001,dev-sensor-002` | Comma-separated valid API keys |
| `MODEL_PATH` | `models/ml/xgboost_detector.pkl` | Path to XGBoost model |
| `SCALER_PATH` | `models/scaler.pkl` | Path to StandardScaler (from Member 2) |
| `FEATURE_NAMES_PATH` | `data/processed/feature_names.json` | Path to feature names JSON |
| `RATE_LIMIT_RPM` | `100` | Max requests per minute per API key |
| `LOG_LEVEL` | `INFO` | Logging level |
| `POSTGRES_DB` | `secopsai` | PostgreSQL database name |
| `POSTGRES_USER` | `secopsai_user` | PostgreSQL user |
| `POSTGRES_PASSWORD` | `your_password_here` | PostgreSQL password |
| `POSTGRES_HOST` | `localhost` | PostgreSQL host |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |

---

## Handoff to Member 6

### Endpoints for integration

| Endpoint | Purpose |
|----------|---------|
| `POST /detect` | Submit network flow features for detection. Returns `request_id`, `verdict`, `latency_ms` |
| `GET /health` | Health check for load balancers and Kubernetes probes |
| `GET /metrics/` | Prometheus metrics for Grafana dashboards |

### Enrichment pipeline flow

Member 6's enrichment pipeline should:

1. Subscribe to network flow data (from Kafka or direct sensor feed)
2. Construct the 37-feature payload for the `/detect` endpoint
3. Send authenticated request with `X-API-Key` header
4. On `"verdict": "MALICIOUS"`:
   - Enrich via VirusTotal and Shodan (see `member6/scripts/`)
   - Send alert via Slack webhook
   - Execute containment action (IP block via iptables)
   - Publish event to Kafka `alert-events` topic

### Kafka integration

For production deployment, publish a message to the `alert-events` Kafka topic when `verdict == "MALICIOUS"`:

```json
{
  "timestamp": "2026-07-02T17:55:48Z",
  "request_id": "1164e4c8-5881-4f3f-bc35-1c82621688bc",
  "verdict": "MALICIOUS",
  "client_ip": "10.0.0.5"
}
```

Feature values must **never** be included in Kafka messages or logs to prevent feature extraction attacks.

### Alert format for Slack

```
*SecOpsAI — Threat Detected*
*Threat Type:* C2 Beaconing
*Source IP:* 192.168.1.5
*Confidence:* N/A (label-only per ADR-004)
*Severity:* HIGH

*VirusTotal Report*
Malicious: 3 | Suspicious: 2 | Harmless: 0

*Shodan Report*
Organization: Example Corp
Country: United States
Open Ports: [22, 80, 443]
```

---

*Deliverable 5 — Production Detection API*
*SecOpsAI | Cohort 2, 2026 | Expadox Lab*
