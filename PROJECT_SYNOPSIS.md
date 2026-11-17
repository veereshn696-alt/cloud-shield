# ACADEMIC PROJECT SYNOPSIS

---

## **PROJECT TITLE:**
# **CLOUDSHIELD: Intelligent Cloud Security Monitoring & Threat Detection Platform**
### *A Freemium, Multi-Tenant Cloud-Based Cybersecurity SaaS Platform*

---

### **ACADEMIC DETAILS**
* **Candidate Name:** Veeresh  
* **USN / Roll Number:** ________________________  
* **Degree / Course:** Bachelor of Computer Applications (BCA)  
* **Department:** School of Computer Science & Applications  
* **Institution:** KLE Technological University  
* **Project Domain:** Cloud Computing & Cybersecurity  
* **Academic Session:** 2026 – 2027  
* **Project Guide:** ________________________  

---

## 1. ABSTRACT

Modern digital organizations rely on cloud-hosted applications, microservices, and distributed web APIs to conduct business. However, every digital interaction generates voluminous security event logs, making manual monitoring impossible. Without automated detection, security incidents such as **brute-force credential stuffing**, **Distributed Denial of Service (DDoS)**, **privilege escalation**, and **anomalous proxy/Tor access** remain unnoticed until severe data compromise occurs.

**CloudShield** is an intelligent, multi-tenant cloud security monitoring and threat detection platform (Mini SIEM) built as a **Freemium Software-as-a-Service (SaaS)** solution. It allows multiple organizations to register, connect their cloud services, ingest security audit logs in real time, and evaluate incoming events against an automated detection engine. 

The platform operates on an elastic freemium cloud model: basic audit logging and rule-based threat mitigation are provided free of cost (₹0/mo), while advanced threat forensics, machine learning anomaly detection, and automated notifications are unlocked via a subscription tier. The system is containerized with Docker, providing high scalability, low latency, and cloud portability.

---

## 2. INTRODUCTION & BACKGROUND

Security Information and Event Management (SIEM) systems are the core defense mechanism of modern Security Operations Centers (SOC). Traditionally, enterprise SIEM solutions (such as Splunk, IBM QRadar, or Microsoft Sentinel) require heavy on-premise hardware, complex licensing, and dedicated security engineers, putting them out of reach for small-and-medium enterprises (SMEs) and academic environments.

With the rise of cloud computing, security must be delivered as a service (**SECaaS - Security as a Service**). By adopting a multi-tenant cloud architecture, a single centralized monitoring platform can securely serve dozens or hundreds of tenant companies. Each tenant enjoys complete logical data isolation while benefiting from shared compute infrastructure and real-time automated incident detection.

---

## 3. PROBLEM STATEMENT

1. **Information Overload:** Cloud applications generate thousands of HTTP and authentication events per minute. Human administrators cannot detect stealthy attack patterns manually.
2. **High Cost of Commercial SIEM:** Existing commercial security suites impose heavy infrastructure and licensing costs, pricing out smaller organizations.
3. **Delayed Incident Response:** Most systems analyze logs in delayed batches (post-incident forensics) rather than performing sub-second, real-time threat mitigation.
4. **Lack of Educational Demonstration Tools:** Most security platforms operate as black boxes, making it difficult for students and researchers to safely simulate and observe live cyberattacks.

---

## 4. OBJECTIVES OF THE PROJECT

1. **Design a Multi-Tenant Cloud Architecture:** Create a centralized platform where multiple organizations can register, manage users, and isolate security event streams.
2. **Implement Real-Time Audit Ingestion:** Capture critical event metadata (timestamp, action code, username, IPv4 address, HTTP user-agent, status, and payload details).
3. **Develop a Zero-Latency Threat Detection Engine:** Implement sliding-window rule algorithms to detect Brute Force attacks, DDoS surges, unauthorized endpoint access, and malicious proxy IPs.
4. **Engineer a Freemium Feature-Gating Mechanism:** Enforce backend authorization so free tenants receive standard protection, while premium features (AI Anomaly Detection) are gated behind subscription status.
5. **Build a Cyber SOC Dashboard:** Design a high-visibility, dark-mode monitoring interface displaying aggregate metrics, live severity-coded alert cards, and activity logs.
6. **Provide a Real-Time Live Ingestion Gateway & Standalone Client Agent:** Build a secure REST endpoint (`POST /api/v1/events`) and zero-dependency terminal agent (`agent.py`) enabling external cloud workloads, servers, and endpoints to securely stream authentic security audit telemetry using tenant API keys.
7. **Ensure Cloud Portability:** Containerize the full stack using Docker and Docker Compose for zero-configuration cloud deployment.

---

## 5. SYSTEM ARCHITECTURE & DATA FLOW

```text
 ┌────────────────────────────────────────────────────────┐
 │           Client Applications / Remote Servers         │
 └───────────────────────────┬────────────────────────────┘
                             │ HTTPS / REST API
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │           FastAPI Gateway & Auth Controller            │
 │     (Input Validation via Pydantic & SHA-256 Auth)     │
 └─────────────┬───────────────────────────┬──────────────┘
               │                           │
               ▼                           ▼
 ┌───────────────────────────┐ ┌───────────────────────────┐
 │   Subscription & Tenant   │ │   Security Engine         │
 │   Access Guard            │ │   • Rule-Based Detector   │
 │   (Free vs. Pro Tier)     │ │   • ML Anomaly Scorer     │
 └─────────────┬─────────────┘ └───────────┬───────────────┘
               │                           │
               └─────────────┬─────────────┘
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │      Multi-Tenant Database (SQLite / PostgreSQL)       │
 │   (Companies, Subscriptions, Activity Logs, Alerts)    │
 └───────────────────────────┬────────────────────────────┘
                             │ Asynchronous Polling (3s)
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │           Interactive Web SOC Dashboard                │
 │       (HTML5, CSS3 Cyber Neon UI, Vanilla JS)          │
 └────────────────────────────────────────────────────────┘
```

---

## 6. MODULE DESCRIPTION

### Module 1: Company Registration & Multi-Tenant Management
* Registers tenant organizations with unique identifiers (`company_id`).
* Issues company API keys for secure log ingestion.
* Guarantees strict logical tenant isolation: users from Company A can never view or query Company B's audit data.

### Module 2: Authentication & Cryptographic Security
* User registration and login utilizing salted **SHA-256** one-way cryptographic hashing.
* Role-based access control distinguishing between `admin` (SOC operators) and regular `user` accounts.

### Module 3: Centralized Audit Logging (SIEM Vault)
* Ingests and structures audit records containing timestamp, action type, IP address, user-agent, status, and contextual details.
* Parameterized SQL execution preventing SQL Injection vulnerabilities.

### Module 4: Real-Time Security Detection Engine
Continuously evaluates live event streams against automated security rules:
1. **Brute Force Detection:** Flags critical incident when $\ge 3$ failed logins occur from the same IP/username within 5 minutes.
2. **DDoS Traffic Rate Surge:** Detects $\ge 15$ HTTP requests in 60 seconds from a single IP address.
3. **Unauthorized Privilege Escalation:** Alerts when unprivileged accounts attempt access to restricted administrative endpoints.
4. **Anomalous Proxy / Tor Exit Nodes:** Flags logins originating from documented Tor exit nodes or malicious IP ranges.

### Module 5: AI / Machine Learning Anomaly Detection (Pro Tier)
* Utilizes **Scikit-learn** (Isolation Forest algorithm) to learn normal baseline behaviors and assign anomaly scores to unusual login hours, request volumes, or unexpected IP deviations.

### Module 6: Freemium Subscription & Feature-Gating Engine
* Maintains tiered plans: **Free (₹0)**, **Professional (₹999)**, and **Enterprise**.
* Server-side permission guards check subscription state before serving advanced analytics or ML anomaly detection endpoints.
* Integrated sandbox payment simulator demonstrating instantaneous tier upgrades.

### Module 7: Cyber SOC Dashboard & Alert Mitigation Desk
* Displays real-time aggregate cards (Total Logs, Normal Events, Suspicious Events, Active Critical Alerts).
* Live severity-coded alert cards (CRITICAL in red, HIGH in orange, MEDIUM in yellow).
* Interactive mitigation workflow allowing SOC operators to resolve active incidents.

### Module 8: Academic Attack Simulation Suite
* Built-in one-click attack triggers allowing real-time demonstrations of Hydra-style credential stuffing, botnet DDoS surges, and unauthorized access scenarios.

---

## 7. DATABASE SCHEMA DESIGN

The relational schema consists of six core entities:

1. **`companies`**: `company_id` (PK), `company_name`, `api_key`, `created_at`
2. **`plans`**: `plan_id` (PK), `plan_name` (FREE, PROFESSIONAL, ENTERPRISE), `price`, `max_users`, `retention_days`
3. **`subscriptions`**: `subscription_id` (PK), `company_id` (FK), `plan_id` (FK), `status`, `start_date`, `end_date`
4. **`users`**: `id` (PK), `company_id` (FK), `username`, `email`, `password_hash`, `role`, `created_at`
5. **`activity_logs`**: `id` (PK), `company_id` (FK), `timestamp`, `username`, `action`, `ip_address`, `user_agent`, `status`, `details`
6. **`security_alerts`**: `id` (PK), `company_id` (FK), `timestamp`, `alert_type`, `severity`, `source_ip`, `target_user`, `message`, `status`, `mitigation_action`

---

## 8. HARDWARE & SOFTWARE REQUIREMENTS

### Software Requirements:
* **Operating System:** Windows 10/11, Linux (Ubuntu 22.04+), or macOS
* **Programming Language:** Python 3.9+ (Python 3.13 recommended)
* **Backend Framework:** FastAPI (v0.115+)
* **ASGI Server:** Uvicorn (v0.30+)
* **Database:** SQLite (embedded RDBMS) / PostgreSQL ready
* **Data Validation:** Pydantic (v2.0+)
* **Frontend Technologies:** HTML5, CSS3 (Custom Dark Cyberpunk Theme), Vanilla JavaScript (ES6+)
* **Containerization:** Docker & Docker Compose
* **Version Control:** Git & GitHub

### Hardware Requirements:
* **Processor:** Intel Core i3 / AMD Ryzen 3 or higher
* **RAM:** 4 GB minimum (8 GB recommended)
* **Storage:** 500 MB free hard disk space
* **Network:** Standard broadband internet connection (for remote API testing and tunneling)

---

## 9. METHODOLOGY & IMPLEMENTATION PHASES

```text
Phase 1: Requirements Analysis & Threat Modeling
         Define attack vectors, SIEM audit needs, and SaaS tiers.
         
Phase 2: Database Schema & Core API Development
         Build tables, seed accounts, implement FastAPI endpoints.

Phase 3: Security Rule Engine Construction
         Implement sliding-window detection algorithms in Python.

Phase 4: Frontend SOC Dashboard & Attack Simulator
         Build cyber dark-mode interface with live polling and simulation buttons.

Phase 5: Multi-Tenancy & Freemium Subscription Gating
         Add company isolation, feature locks, and sandbox checkout flow.

Phase 6: Containerization, Testing & Academic Documentation
         Dockerize system, execute unit/integration tests, and prepare Viva defense.
```

---

## 10. EXPECTED OUTCOMES & ACADEMIC DELIVERABLES

1. **Fully Functional Cloud Web Application:** A live, containerized, multi-tenant cybersecurity SIEM dashboard.
2. **Automated Threat Detection Demo:** Live demonstration of Brute Force, DDoS, and Privilege Escalation detection with instant alert mitigation.
3. **Freemium SaaS Implementation:** Functional demonstration of feature gating and real-time subscription upgrade.
4. **Source Code Repository:** Clean, modular, and documented codebase organized following microservice best practices.
5. **Project Report & Presentation Deck:** Complete project documentation and seminar slide presentation.

---

## 11. CONCLUSION

**CloudShield** bridges the gap between academic theory and industry practice by merging **Cloud Computing** (multi-tenancy, SaaS distribution, Docker containerization) with **Cybersecurity** (SIEM log ingestion, automated threat detection, incident mitigation). The project delivers a practical, scalable, and economically feasible security platform suitable for modern cloud environments and serves as a strong academic capstone.

---

### **SIGNATURES FOR APPROVAL**

\
**Student Signature:** _____________________________  
**Date:** _____________________________  

\
**Project Guide Signature:** _____________________________  
**Head of Department (HOD) Signature:** _____________________________  
