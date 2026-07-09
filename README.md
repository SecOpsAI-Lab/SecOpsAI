# Member 6 — SecOps, Pipeline & Observability Engineer

## SecOpsAI — Adversarial AI Detection Engineering Project
**Expadox Lab | Cohort 2, 2026**

---

## Overview
As Member 6, I built the final integration layer of the SecOpsAI platform —
wiring the full detection pipeline from alert enrichment to automated 
containment, real-time dashboards, and CI/CD regression testing.

---

## Deliverables

### 1. Alert Enrichment Pipeline
- Receives detection events from Member 5's FastAPI detection service
- Enriches alerts with **VirusTotal** (malicious IP reputation check)
- Enriches alerts with **Shodan** (open ports, organisation, country)
- Sends fully enriched alerts to **Slack** in real time

### 2. Automated Containment Actions
- **Firewall Rule Injection** — blocks confirmed malicious IPs via iptables
- **Host Isolation Mock** — quarantines endpoint on high-confidence alert
- **User Account Disable** — revokes access on privilege escalation alert
- All actions logged to `containment_log.txt` with timestamps

### 3. Wazuh SIEM
- Wazuh Manager, Indexer and Dashboard running via Docker
- Real-time security event monitoring on Kali environment
- Detected: sudo executions, login sessions, port changes, rootcheck anomalies
- AWS CloudTrail threat intelligence integration active

### 4. Grafana Dashboard
- 3 monitoring panels:
  - **Detection Rate** — alerts per hour over rolling window
  - **False Positive %** — FP trend with threshold markers
  - **Model Health** — drift, confidence distribution, latency
- Ready to connect to Member 5 Prometheus metrics endpoint

### 5. GitHub Actions CI/CD Pipeline
- Triggers on every push to `main` or `member6-secops` branch
- Steps: Lint → Unit Tests → Docker Build → Detection Regression → Deploy
- Enforces 80% test coverage minimum
- Slack notification on pipeline failure

---

## Scripts

| Script | Description |
|--------|-------------|
| `scripts/slack_alert.py` | Sends enriched alerts to Slack webhook |
| `scripts/virustotal_check.py` | Checks IP reputation via VirusTotal API |
| `scripts/shodan_check.py` | Gets port and geo data via Shodan API |
| `scripts/enrichment_pipeline.py` | Full pipeline — detection to alert |
| `scripts/containment.py` | Automated IP blocking via iptables |

---

## Tools & Technologies
- **SIEM:** Wazuh (Manager + Indexer + Dashboard)
- **Dashboards:** Grafana + Prometheus
- **Enrichment:** VirusTotal API + Shodan API
- **Alerting:** Slack Webhook
- **Containment:** iptables (Linux firewall)
- **CI/CD:** GitHub Actions
- **Language:** Python 3.11+
- **Infrastructure:** Docker + Docker Compose

---

## Pipeline Flow

Member 5 Detection API
↓
Enrichment Pipeline
↓
VirusTotal Check → Shodan Check
↓
Slack Alert (full enriched report)
↓
Containment Action (IP block)
↓
Wazuh logs everything
↓
Grafana displays metrics

---

## Integration with Member 5
- Endpoint: `POST /detect`
- Auth: `X-API-Key: dev-sensor-001`
- Pipeline triggers on `"verdict": "MALICIOUS"`
- Awaiting Member 5 API IP address for live integration

---

## Evidence
Screenshots are in the `evidence/` folder showing:
- Wazuh dashboard with real security events
- Grafana dashboard with 3 monitoring panels
- Terminal output showing VirusTotal and Shodan enrichment
- Slack channel receiving enriched threat alerts
- Containment script successfully blocking malicious IP
- GitHub Actions CI/CD workflow

---

*SecOpsAI | Member 6 | Expadox Lab Cohort 2, 2026*
