# 🛡️ CloudShield: Intelligent Cloud Security Monitoring & Threat Detection Platform

[![Python](https://img.shields.io/badge/Python-3.13+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![SQLite](https://img.shields.io/badge/SQLite-3.0+-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/Tests-7%20Passed%20(100%25)-success?style=for-the-badge&logo=pytest&logoColor=white)](tests/test_cloudshield.py)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

> **CloudShield** is a modern, lightweight **Freemium Multi-Tenant Cloud Cybersecurity & Security Information and Event Management (SIEM) Platform**. Delivered as a **Security-as-a-Service (SECaaS)** solution, CloudShield allows multiple client organizations to ingest real-time HTTP audit telemetry, detect cyber threats with sub-second latency, and leverage Machine Learning behavioral anomaly detection.

---

## 🌟 Key Features

* **🏢 Multi-Tenant Cloud Architecture:** Strict logical data partitioning by `company_id`. Multiple organizations safely share the central backend and database with guaranteed data isolation.
* **📡 Real-Time Ingestion Gateway (`POST /api/v1/events`):** Authenticates incoming log streams using cryptographically generated Tenant API Keys (`X-API-Key` or JSON body).
* **⚡ Sub-15ms Threat Detection Engine:** Sliding-window SQL rule evaluation:
  * **Brute Force:** $\ge 3$ failed logins from the same IP/user within 5 minutes $\rightarrow$ **CRITICAL Alert**.
  * **DDoS Surge:** $\ge 15$ HTTP requests in 60 seconds from a single IP $\rightarrow$ **HIGH Alert**.
  * **Privilege Escalation:** Unauthorized access to superadmin endpoints $\rightarrow$ **HIGH Alert**.
  * **Anomalous Proxy/Tor Nodes:** Ingress from known Tor Exit Nodes ($185.220.*$) $\rightarrow$ **MEDIUM Alert**.
* **🧠 Machine Learning Behavioral Anomaly Scoring:** Evaluates request velocity bursts, failure concentration ratios, off-hours access (01:00 AM – 05:00 AM), and geo-dispersion to detect stealthy exfiltration.
* **💎 Freemium SaaS & Feature Gating:** Free essential tier (₹0/mo) with standard SOC features, alongside a Professional Tier (₹999/mo) unlocking AI Anomaly Detection via live sandbox checkout simulation.
* **📥 Compliance & Forensic Export:** One-click downloads for **CSV Audit Logs** and **JSON Incident Reports** aligned with ISO/IEC 27001 audit readiness.
* **📡 Standalone Client Agent (`agent.py`):** Zero-dependency Python CLI tool for pinging the gateway, continuous telemetry streaming, and generating authentic network attack scenarios.
* **🖥️ Dark-Mode Cyber SOC Dashboard:** Real-time web console with 3-second asynchronous polling, instant incident mitigation, and live tenant switching.

---

## 📐 System Architecture

```text
  ┌───────────────────────────────────────────────────────────────┐
  │         External Servers / Microservices / Client Agent       │
  │                    (agent.py / Web Apps)                      │
  └───────────────────────────────┬───────────────────────────────┘
                                  │ HTTP POST /api/v1/events
                                  │ (X-API-Key: tenant_key)
                                  ▼
  ┌───────────────────────────────────────────────────────────────┐
  │                 CloudShield FastAPI Backend (ASGI)            │
  ├───────────────────────────────────────────────────────────────┤
  │  • Tenant Authentication & API Key Validation                 │
  │  • Cryptographic Passwords (SHA-256)                          │
  │  • Activity Log Vault Ingestion                               │
  ├───────────────────────────────┬───────────────────────────────┤
  │                               │                               │
  ▼                               ▼                               ▼
┌──────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Rule-Based Threat│    │ AI ML Behavioral │    │ Freemium Feature│
│ Detection Engine │    │  Anomaly Scorer  │    │  Gating Guard   │
│  (Sliding Window)│    │ (4-Vector Model) │    │  (Free vs. Pro) │
└─────────┬────────┘    └─────────┬────────┘    └────────┬────────┘
          │                       │                      │
          └───────────────────────┼──────────────────────┘
                                  ▼
  ┌───────────────────────────────────────────────────────────────┐
  │        SQLite Storage (Partitioned by company_id)             │
  │     companies | plans | subscriptions | logs | alerts         │
  └───────────────────────────────┬───────────────────────────────┘
                                  │ 3-Second Async Polling
                                  ▼
  ┌───────────────────────────────────────────────────────────────┐
  │               Cyber SOC Monitoring Web Dashboard              │
  │            (http://127.0.0.1:8000 - Vanilla JS & CSS3)        │
  └───────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start Guide

### Prerequisites
* Python 3.10 or higher
* Git

### 1. Clone the Repository
```bash
git clone https://github.com/veeresh/CloudShield.git
cd CloudShield
```

### 2. Set Up Virtual Environment & Install Dependencies
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Launch the Platform
```bash
# Option A: Direct Python (Recommended)
python -m uvicorn main:app --host 127.0.0.1 --port 8000

# Option B: Windows 1-Click Launcher
start_server.bat
```

Open your browser and navigate to:
👉 **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

---

## 🎮 Live Demonstrations

### 1. Automated 2-Minute Viva Showcase
Experience all 8 core pillars of CloudShield automatically with interactive step pauses:
```bash
python demo.py
```
*(Or run non-stop with `python demo.py --auto`)*

### 2. Stream Real-Time Logs via Client Agent
Run the standalone agent in another terminal to simulate live host traffic or launch authentic cyber attacks:
```bash
# Check gateway status
python agent.py --status

# Stream continuous host telemetry every 3 seconds
python agent.py --stream

# Trigger real live HTTP attack scenarios
python agent.py --attack brute-force
python agent.py --attack ddos
python agent.py --attack unauthorized
python agent.py --attack tor-exit

# Transmit a custom event
python agent.py --send --action LOGIN_FAILED --user admin --ip 192.168.1.105
```

---

## 🧪 Automated Testing

CloudShield includes comprehensive unit tests verifying multi-tenancy, SHA-256 cryptography, sliding-window rule evaluation, subscription gating, and AI scoring:

```bash
pytest tests/test_cloudshield.py -v
```

**Test Results:**
```text
tests/test_cloudshield.py::test_company_listing_and_seeding PASSED       [ 14%]
tests/test_cloudshield.py::test_password_hashing_and_user_creation PASSED [ 28%]
tests/test_cloudshield.py::test_multi_tenant_data_isolation PASSED       [ 42%]
tests/test_cloudshield.py::test_brute_force_rule_detection PASSED        [ 57%]
tests/test_cloudshield.py::test_freemium_subscription_upgrade PASSED     [ 71%]
tests/test_cloudshield.py::test_ai_anomaly_scoring_model PASSED          [ 85%]
tests/test_cloudshield.py::test_api_key_lookup_and_event_ingestion PASSED [100%]
============================== 7 passed in 0.44s ==============================
```

---

## 🐳 Docker Deployment

To deploy CloudShield inside an isolated container:

```bash
# Build and start container
docker-compose up --build

# Run in background
docker-compose up -d
```
Access the containerized platform at `http://localhost:8000`.

---

## 📡 REST API Reference

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/ping` | Gateway health check & capabilities | None |
| `POST` | `/api/v1/events` | Ingest real-time security audit event | `X-API-Key` |
| `GET` | `/api/companies` | List all enrolled tenant companies | Public |
| `POST` | `/api/companies/register` | Onboard a brand new tenant organization | Public |
| `POST` | `/api/subscriptions/upgrade` | Upgrade subscription plan (Sandbox checkout) | Public |
| `GET` | `/api/pro/ai-anomalies` | Feature-gated AI behavioral anomaly scores | Pro / Enterprise |
| `GET` | `/api/admin/metrics` | Aggregate SOC dashboard counters | Scoped by tenant |
| `GET` | `/api/admin/alerts` | Query active and historical threat incidents | Scoped by tenant |
| `POST` | `/api/admin/alerts/{id}/resolve`| Mitigate and resolve an active incident | Admin |
| `GET` | `/api/admin/export/logs` | Download compliance audit logs as CSV | Scoped by tenant |
| `GET` | `/api/admin/export/alerts` | Download security incidents as JSON | Scoped by tenant |

---

## 📁 Repository Structure

```text
mini_project/
├── agent.py                            # Standalone Python client agent & attack generator
├── demo.py                             # Interactive automated showcase script
├── main.py                             # FastAPI REST application & routing
├── database.py                         # Multi-tenant SQLite schema & queries
├── security_engine.py                  # Sliding-window rule detection algorithms
├── ml_engine.py                        # Behavioral anomaly scoring model
├── start_server.bat                    # 1-Click Windows desktop launcher
├── Dockerfile                          # Container specification
├── docker-compose.yml                  # Multi-container orchestration
├── requirements.txt                    # Project Python dependencies
├── CloudShield_Seminar_Presentation.pptx # 12-slide academic presentation deck
├── PROJECT_REPORT.md                   # Full 7-chapter project report
├── PROJECT_SYNOPSIS.md                 # Academic project synopsis
├── VIVA_VOCE_GUIDE.md                  # Top 20 Examiner Q&A Guide
├── tests/
│   └── test_cloudshield.py             # 7 Automated Pytest test cases
└── static/
    ├── index.html                      # Dark-mode SOC Cyber Web Dashboard
    ├── styles.css                      # Modern cybersecurity UI styling
    └── app.js                          # Asynchronous dashboard controller & polling
```

---

## 👤 Author & Academic Details

* **Author:** Veeresh
* **Degree:** Bachelor of Computer Applications (BCA)
* **Department:** School of Computer Science & Applications
* **Institution:** KLE Technological University, Hubballi
* **Project Domain:** Cloud Computing & Cybersecurity (SECaaS / SIEM)

---

## 📄 License
This project is open-source and available under the [MIT License](LICENSE).
