# SecOpsAI – STRIDE Threat Model
**Deliverable 1 | Security Architecture and Threat Model**
**Status:** Complete | **Author:** Member 1 – Security Architect
**Based on:** System Context Diagram + Level-1 DFD with Trust Boundaries

---

## 1. System Overview

SecOpsAI is an AI-powered threat detection and automated response platform. It ingests raw network traffic (PCAP) and endpoint logs, extracts behavioral features, classifies threats using ML, enriches alerts via external APIs, and executes automated containment actions.

**Trust Boundaries Defined:**
| Boundary | Components | Trust Level |
|----------|-----------|-------------|
| Sensor Boundary | Network Sensors (Zeek/Suricata), Endpoint Log Agents | Semi-Trusted |
| Internet Boundary | VirusTotal API, Shodan API, Slack/Email | Untrusted External |
| API Boundary | FastAPI Service (POST /detect) | Public Attack Surface |
| Model Boundary | ML Detection Engine, PostgreSQL, Feature Engineering | Highest-Value Assets |

---

## 2. STRIDE Threat Model

### S – Spoofing

| # | Threat | Component | MITRE ATT&CK | Mitigation |
|---|--------|-----------|--------------|-----------|
| S1 | Attacker spoofs network sensor identity to inject false PCAP data | Network Sensors / Zeek | T1001 – Data Obfuscation | Mutual TLS between sensors and ingestion pipeline; sensor certificates enforced |
| S2 | Attacker spoofs API client identity to submit crafted detection requests | FastAPI /detect endpoint | T1078 – Valid Accounts | JWT authentication with short-lived tokens; API key rotation policy |
| S3 | Attacker spoofs VirusTotal/Shodan API responses via DNS hijacking | Threat Enrichment Layer | T1584 – Compromise Infrastructure | Pin expected TLS certificates; validate response schemas before use |
| S4 | Attacker impersonates SOC analyst to access Grafana dashboards | Observability Layer | T1078.004 – Cloud Accounts | Role-based access control (RBAC); MFA enforced for dashboard access |

---

### T – Tampering

| # | Threat | Component | MITRE ATT&CK | Mitigation |
|---|--------|-----------|--------------|-----------|
| T1 | Attacker tampers with PCAP files before ingestion to corrupt feature extraction | Feature Extractor | T1565.001 – Stored Data Manipulation | Tamper-evident logging with SHA-256 hash verification on every ingested file |
| T2 | Adversarial data injection into Kafka topic raw-features to poison ML features | Kafka Topic (raw-features) | T1565 – Data Manipulation | Kafka ACLs; producer authentication; schema validation on every message |
| T3 | Data poisoning attack: attacker injects mislabelled training samples to degrade model accuracy | ML Detection Engine / Training Pipeline | T1600 – Weaken Encryption (analog) / AML.T0020 – Poison Training Data | Signed datasets; anomaly detection on training data distribution; MLflow model provenance tracking |
| T4 | Attacker modifies model artifacts stored in MLflow between training and serving | MLflow / Model Boundary | T1565.001 | Cryptographic signing of model artifacts; hash verification before loading |
| T5 | PostgreSQL audit logs tampered to cover attacker activity | PostgreSQL | T1565.003 – Runtime Data Manipulation | Append-only audit log table; log shipping to separate immutable store |

---

### R – Repudiation

| # | Threat | Component | MITRE ATT&CK | Mitigation |
|---|--------|-----------|--------------|-----------|
| R1 | API caller denies submitting malicious detection request | FastAPI /detect | T1562.006 – Indicator Blocking | Structured audit log (timestamp, JWT subject, request payload hash, response) written to PostgreSQL on every call |
| R2 | Automated response action (firewall block, host isolation) disputed | Notification / Automated Response Layer | T1562 – Impair Defenses | Immutable action log; every containment action logged with trigger alert ID and timestamp before execution |
| R3 | Training run outcome disputed | MLflow | T1070 – Indicator Removal | MLflow experiment tracking captures all hyperparameters, dataset hashes, and metrics per run |

---

### I – Information Disclosure

| # | Threat | Component | MITRE ATT&CK | Mitigation |
|---|--------|-----------|--------------|-----------|
| I1 | Model inversion / membership inference attack extracts training data from ML model | ML Detection Engine | AML.T0024 – Infer Training Data | Prediction-only API; no raw probabilities or gradients exposed; rate limiting on /detect |
| I2 | API response leaks internal system details (stack traces, model version) | FastAPI /detect | T1592 – Gather Victim Host Information | Structured error responses only; no stack traces in production; version header suppressed |
| I3 | Kafka topics readable by unauthorized internal services | Kafka Topics | T1040 – Network Sniffing | Kafka ACLs enforced per topic; encryption in transit (TLS); separate consumer groups per service |
| I4 | PostgreSQL credentials exposed in environment variables or source code | PostgreSQL | T1552.001 – Credentials in Files | Secrets managed via environment injection (Docker secrets or Vault); never committed to Git |
| I5 | VirusTotal/Shodan API keys leaked via logs or error messages | Threat Enrichment Layer | T1552 – Unsecured Credentials | API keys loaded from secrets manager; scrubbed from all log output |

---

### D – Denial of Service

| # | Threat | Component | MITRE ATT&CK | Mitigation |
|---|--------|-----------|--------------|-----------|
| D1 | Attacker floods /detect endpoint with high-volume requests to exhaust inference capacity | FastAPI /detect | T1499 – Endpoint Denial of Service | Rate limiting (per-IP and per-token); p99 latency monitored via Prometheus; circuit breaker pattern |
| D2 | Kafka topic overwhelmed with crafted high-volume messages, starving ML engine | Kafka Topics | T1498 – Network Denial of Service | Topic-level message rate limits; consumer lag monitoring in Grafana |
| D3 | Resource exhaustion via extremely large PCAP files submitted to ingestion | Feature Extractor | T1499.003 – Application Exhaustion Flood | Maximum file size enforced at ingestion; async processing with queue backpressure |
| D4 | CI/CD pipeline triggered repeatedly via forged webhook events | GitHub Actions | T1195 – Supply Chain Compromise | Webhook secret validation; GitHub Actions concurrency limits; branch protection rules |

---

### E – Elevation of Privilege

| # | Threat | Component | MITRE ATT&CK | Mitigation |
|---|--------|-----------|--------------|-----------|
| E1 | Model evasion attack: adversarially crafted traffic bypasses ML detector and reaches production systems undetected | ML Detection Engine | AML.T0015 – Evade ML Model | Adversarial retraining with IBM ART; ensemble detection (rule-based + ML); confidence threshold alerting |
| E2 | Attacker exploits FastAPI input validation failure to achieve remote code execution | FastAPI /detect | T1190 – Exploit Public-Facing Application | Strict input validation (Pydantic schemas); no dynamic code execution from user input; container isolation |
| E3 | Compromised SOC analyst account used to approve and escalate false containment actions | Notification / Automated Response | T1078 – Valid Accounts | Least privilege on containment actions; two-person approval for destructive actions (host isolation, user disable) |
| E4 | Container escape from detection service container to host | Docker (FastAPI container) | T1611 – Escape to Host | Non-root container execution; read-only filesystem where possible; seccomp/AppArmor profiles |

---

## 3. AI-Specific Threats Summary

| Threat Type | Where | Mitigation |
|-------------|-------|-----------|
| Data Poisoning | Training Pipeline / Kafka | Signed datasets, distribution monitoring, tamper-evident logs |
| Model Evasion | ML Detection Engine | Adversarial retraining, IBM ART, ensemble with rule baseline |
| Membership Inference | FastAPI /detect API | Prediction-only responses, rate limiting, no gradient exposure |
| Model Theft | MLflow / Model Artifacts | Artifact signing, access control, no model weights in API response |

---

## 4. Architecture Decision Record (ADR)

### ADR-001: Kafka for Feature Transport (not direct DB writes)
**Decision:** Use Kafka topics (raw-features, processed-features, alert-events) to decouple pipeline stages.
**Rationale:** Provides backpressure, replay capability, and isolates ingestion failures from the ML engine.
**Security implication:** Kafka ACLs and TLS required; adds an attack surface that must be monitored.
**Rejected alternative:** Direct PostgreSQL writes from sensors — too tightly coupled, no replay, harder to scale.

### ADR-002: Rule-Based Baseline Before ML
**Decision:** Snort/Suricata rules built and benchmarked before ML training begins.
**Rationale:** Establishes a performance floor; ML must beat baseline by ≥15% F1. Prevents over-reliance on opaque model.
**Security implication:** Rule baseline remains active as a fallback if ML model is retracted after evasion discovery.

### ADR-003: Prediction-Only API (No Gradient/Probability Exposure)
**Decision:** FastAPI /detect returns classification label and confidence band only — no raw softmax scores.
**Rationale:** Reduces membership inference and model inversion attack surface.
**Rejected alternative:** Returning full probability vector — provides too much information for adversarial probing.

### ADR-004: Adversarial Retraining via IBM ART
**Decision:** IBM Adversarial Robustness Toolbox used for attack simulation and adversarial example generation.
**Rationale:** Industry-standard framework; integrates with scikit-learn and PyTorch; produces reproducible attack metrics.
**Constraint:** System must survive ≥3 of 6 crafted evasion attacks post-hardening (project requirement).

### ADR-005: Immutable Audit Logs to Separate Store
**Decision:** All audit events (API calls, containment actions, model predictions) written to an append-only PostgreSQL table and shipped to a separate log store.
**Rationale:** Prevents an attacker who compromises the detection service from covering their tracks by modifying logs.

### ADR-006: Threat Enrichment via External APIs (Untrusted Boundary)
**Decision:** VirusTotal and Shodan treated as untrusted external services; responses validated against schema before use.
**Rationale:** External APIs can return malformed or manipulated data. Schema validation prevents injection via enrichment response.

---

## 5. MITRE ATT&CK Navigator Layers

The following techniques are covered in this threat model and should be imported into MITRE ATT&CK Navigator:

- T1001, T1040, T1070, T1078, T1078.004, T1098, T1190, T1195, T1498, T1499, T1499.003, T1522, T1552, T1552.001, T1562, T1562.006, T1565, T1565.001, T1565.003, T1584, T1592, T1600, T1611
- AI/ML Specific (ATLAS): AML.T0015, AML.T0020, AML.T0024

---

*Document prepared by Member 1 – Security Architect*
*SecOpsAI | Cohort 2, 2026 | Expadox Lab – Do not share outside the program*
