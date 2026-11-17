# 🛡️ Academic Project Report: Cloud Security Monitoring & Threat Detection Platform (Mini SIEM)

**Academic Level:** BCA / BSc Computer Science / B.Tech  
**Domain:** Cloud Computing & Cybersecurity  
**Technology Stack:** Python, FastAPI, SQLite, Docker, Vanilla HTML5 / CSS3 / JavaScript  

---

## 📌 Executive Summary

Modern cloud-hosted web applications process thousands of user interactions and API calls daily. Manual inspection of system audit logs is impossible. Without automated threat detection, cyberattacks such as **Brute-Force Credential Stuffing**, **Distributed Denial of Service (DDoS)**, **Privilege Escalation**, and **Proxy/Tor Anomaly Logins** go unnoticed until critical damage occurs.

This project implements an **Intelligent Cloud Security Monitoring & Threat Detection Platform (Mini SIEM)**. It ingests application logs in real time, evaluates them against automated security rules, triggers incident mitigation alerts, and provides a Security Operations Center (SOC) dashboard for security administrators.

---

## 🏗️ System Architecture

```text
                               ┌─────────────────────────┐
                               │  User / Client Browser  │
                               └────────────┬────────────┘
                                            │
                                            ▼
                               ┌─────────────────────────┐
                               │  FastAPI REST Server    │
                               │  (Authentication & API) │
                               └────────────┬────────────┘
                                            │
                     ┌──────────────────────┴──────────────────────┐
                     │                                             │
                     ▼                                             ▼
        ┌─────────────────────────┐                   ┌─────────────────────────┐
        │  SQLite Database        │                   │  Security Rule Engine   │
        │  (Users, Logs, Alerts)  │                   │  (Real-Time Detection)  │
        └─────────────────────────┘                   └────────────┬────────────┘
                                                                   │
                                                                   ▼
                                                      ┌─────────────────────────┐
                                                      │  Cyber SOC Dashboard    │
                                                      │  (Real-Time Analytics)  │
                                                      └─────────────────────────┘
```

---

## 🗄️ Database Schema Design

The application utilizes an SQLite relational database with three core tables:

### 1. `users` (User Management & Roles)
| Field | Type | Description |
|---|---|---|
| `id` | INTEGER (PK) | Primary Key ID |
| `username` | TEXT (UNIQUE) | Account Username |
| `email` | TEXT (UNIQUE) | User Email Address |
| `password_hash` | TEXT | SHA-256 Hashed Credential |
| `role` | TEXT | Access Level (`admin` / `user`) |
| `created_at` | DATETIME | Registration Timestamp |

### 2. `activity_logs` (Audit Log Stream)
| Field | Type | Description |
|---|---|---|
| `id` | INTEGER (PK) | Log Entry Primary Key |
| `timestamp` | DATETIME | Event Timestamp |
| `username` | TEXT | Associated Account |
| `action` | TEXT | Action Code (`LOGIN_SUCCESS`, `LOGIN_FAILED`, `UNAUTHORIZED_ACCESS`, `API_REQUEST`) |
| `ip_address` | TEXT | Source Client IPv4 Address |
| `user_agent` | TEXT | Client Browser / Device User-Agent |
| `status` | TEXT | Result (`SUCCESS`, `FAILURE`, `BLOCKED`) |
| `details` | TEXT | Additional Context Details |

### 3. `security_alerts` (Incident Management)
| Field | Type | Description |
|---|---|---|
| `id` | INTEGER (PK) | Incident Primary Key |
| `timestamp` | DATETIME | Incident Detection Time |
| `alert_type` | TEXT | Attack Type Classification |
| `severity` | TEXT | Threat Severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) |
| `source_ip` | TEXT | Attacker Source IP |
| `target_user` | TEXT | Target User / System Resource |
| `message` | TEXT | Detailed Threat Analysis Message |
| `status` | TEXT | Incident Status (`ACTIVE`, `RESOLVED`) |
| `mitigation_action`| TEXT | Recommended / Automated Mitigation Action |

---

## ⚡ Threat Detection Rule Engine

The Security Engine (`security_engine.py`) continuously evaluates live logs against 4 automated security detection rules:

| Rule Name | Detection Condition | Severity | Automated Mitigation |
|---|---|---|---|
| **Brute Force Detection** | &ge; 3 failed logins from same IP/Username in 5 mins | **CRITICAL** | Auto-block IP & Enforce CAPTCHA |
| **DDoS Rate Surge** | &ge; 15 HTTP API requests in 60s from single IP | **HIGH** | Rate-limit IP & Challenge WAF |
| **Unauthorized Escalation** | Attempting restricted admin endpoints without credentials | **HIGH** | Revoke Token & Require Re-Auth |
| **Anomalous Proxy IP** | Logins originating from known Tor exit / malicious ranges | **MEDIUM** | Trigger 2FA Verification |

---

## 💻 Running the Application Locally

### 1. Requirements
- Python 3.9+
- Pip package manager

### 2. Start Backend Server
```bash
# Navigate to project directory
cd c:\Users\veere\OneDrive\Desktop\mini_project

# Install dependencies
pip install -r requirements.txt

# Start uvicorn server
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

### 3. Open Web SOC Dashboard
Navigate to `http://127.0.0.1:8000` in your web browser.

---

## 🐳 Docker Deployment (Cloud Containerization)

To deploy on AWS, Azure, or DigitalOcean:

```bash
# Build Docker image
docker build -t cloudsec-siem .

# Run container
docker run -d -p 8000:8000 --name cloudsec_app cloudsec-siem
```

Or using Docker Compose:
```bash
docker-compose up -d
```

---

## 🎓 Viva Voce & Professor Defense Q&A

**Q1: How does this project combine Cloud Computing and Cybersecurity?**  
> *Answer:* The cloud component is demonstrated through containerized microservice architecture (FastAPI + Docker) ready for stateless deployment on cloud providers (AWS EC2). The cybersecurity component implements Security Information and Event Management (SIEM) concepts: centralized audit logging, rule-based threat detection, and incident response mitigation.

**Q2: What is the difference between rule-based detection and machine learning anomaly detection?**  
> *Answer:* Rule-based detection relies on strict threshold conditions (e.g., 3 failed logins = Brute Force). Machine Learning anomaly detection learns statistical baselines of normal traffic and flags deviations. Our project uses a rule engine for predictable zero-latency alerting and can be extended with Scikit-learn for anomaly scoring.

**Q3: How are passwords secured?**  
> *Answer:* Passwords are never stored in plain text. They are hashed using SHA-256 with salted digest comparison before database storage.
