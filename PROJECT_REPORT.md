# ACADEMIC PROJECT REPORT

---

# **CLOUDSHIELD: Intelligent Cloud Security Monitoring & Threat Detection Platform**
### *A Freemium, Multi-Tenant Cloud-Based Cybersecurity SaaS Platform*

**A Project Report Submitted in Partial Fulfillment of the Requirements for the Degree of**  
### **BACHELOR OF COMPUTER APPLICATIONS (BCA)**

---

### **CANDIDATE INFORMATION**
* **Student Name:** Veeresh  
* **USN / Roll Number:** ___________________________  
* **Department:** School of Computer Science & Applications  
* **Institution:** KLE Technological University  
* **Academic Year:** 2026 – 2027  
* **Project Guide:** ___________________________  

---

## 📜 CERTIFICATE OF APPROVAL

This is to certify that the project work entitled **"CLOUDSHIELD: Intelligent Cloud Security Monitoring & Threat Detection Platform"** is a bona fide work carried out by **Veeresh** in partial fulfillment for the award of the degree of **Bachelor of Computer Applications (BCA)** of **KLE Technological University** during the academic year 2026 – 2027.

\
\
__________________________________ \
**Internal Project Guide**  
Department of Computer Applications  
KLE Technological University  

\
\
__________________________________ \
**Head of Department (HOD)**  
School of Computer Science & Applications  
KLE Technological University  

---

## 📑 TABLE OF CONTENTS

1. **Chapter 1: Introduction**
   * 1.1 Project Overview & Domain
   * 1.2 Problem Statement
   * 1.3 Objectives of the Project
   * 1.4 Scope and Applicability
2. **Chapter 2: Literature Survey & Feasibility Study**
   * 2.1 Existing Security Systems vs. CloudShield
   * 2.2 Security as a Service (SECaaS) Model
   * 2.3 Feasibility Analysis (Technical, Operational, Economic)
3. **Chapter 3: Software Requirement Specification (SRS)**
   * 3.1 Functional Requirements
   * 3.2 Non-Functional Requirements
   * 3.3 Hardware Requirements
   * 3.4 Software Requirements
4. **Chapter 4: System Design & Architecture**
   * 4.1 System Architectural Design
   * 4.2 Multi-Tenant Data Isolation Model
   * 4.3 Database Schema Design & ER Specification
   * 4.4 Data Flow Diagrams (DFD Level 0 & Level 1)
5. **Chapter 5: Implementation Details & Algorithms**
   * 5.1 Technology Stack & Framework Justifications
   * 5.2 Threat Detection Rule Algorithms
   * 5.3 AI & Machine Learning Anomaly Scoring Model
   * 5.4 Freemium Access Gating & Subscription Logic
6. **Chapter 6: Software Testing & Experimental Results**
   * 6.1 Testing Methodology
   * 6.2 Automated Pytest Suite Results
   * 6.3 Test Cases Execution Matrix
   * 6.4 Attack Simulation Scenarios
7. **Chapter 7: Conclusion & Future Scope**
   * 7.1 Summary of Contributions
   * 7.2 Future Enhancements
8. **References & Bibliography**

---

## CHAPTER 1: INTRODUCTION

### 1.1 Project Overview & Domain
In today's interconnected digital economy, cloud computing has become the backbone for hosting modern web applications, microservices, and mobile backends. As organizations migrate infrastructure to public and hybrid cloud environments, they face unprecedented cybersecurity challenges. Every interaction—user authentication, database access, REST API consumption—produces digital event trails known as audit logs.

Without automated monitoring, malicious activities such as **Brute-Force Credential Stuffing**, **Distributed Denial of Service (DDoS)**, **Privilege Escalation**, and **Anomalous Proxy Infiltrations** frequently remain undetected until significant financial and reputational damage occurs.

**CloudShield** is an intelligent, multi-tenant cloud security monitoring and threat detection platform (Mini SIEM) built as a **Freemium Software as a Service (SaaS)** solution. It allows multiple tenant organizations to securely ingest audit logs in real time, evaluate events against an automated detection engine, visualize security postures on a Security Operations Center (SOC) dashboard, and mitigate active attacks with one click.

### 1.2 Problem Statement
1. **Information Overload:** Cloud platforms generate thousands of event records every minute. Manual log analysis is physically impossible for human security teams.
2. **Prohibitive Cost of Commercial SIEM Tools:** Enterprise solutions such as Splunk, IBM QRadar, or Microsoft Sentinel demand massive licensing budgets, dedicated infrastructure, and specialized staff, making them inaccessible for small-to-medium enterprises (SMEs) and academic labs.
3. **Delayed Incident Detection:** Traditional tools rely on batch log processing, detecting attacks hours or days after the incident has already concluded.
4. **Lack of Educational / Simulation Environments:** Proprietary tools do not provide safe, integrated attack simulators allowing security students and analysts to test detection rules dynamically.

### 1.3 Objectives of the Project
* **Objective 1:** Implement a **Multi-Tenant Cloud Architecture** capable of serving multiple independent organizations on a single shared compute instance while guaranteeing strict logical data isolation.
* **Objective 2:** Build a **Zero-Latency Ingestion Engine** that captures and structures incoming audit logs (Action, IP address, Username, Status, Timestamp).
* **Objective 3:** Implement an **Automated Threat Detection Engine** with sliding-window rule algorithms that detect Brute Force, DDoS surges, unauthorized access, and Tor proxy IPs.
* **Objective 4:** Develop an **AI & Machine Learning Anomaly Detection Model** that evaluates multidimensional behavioral deviations (velocity, failure concentration, off-hours access).
* **Objective 5:** Engineer a **Freemium Feature-Gating Mechanism** that enforces access control at the API level (Free Tier vs. Professional Tier ₹999/mo).
* **Objective 6:** Design an interactive, cyber-themed **SOC Dashboard** with 3-second real-time asynchronous polling.
* **Objective 7:** Containerize the entire application using **Docker & Docker Compose** for cloud portability and deployment.

### 1.4 Scope and Applicability
CloudShield is designed to serve as an accessible Security Information and Event Management (SIEM) solution for startups, educational institutions, and cloud web applications. It serves as both an operational monitoring defense tool and an academic simulation workbench.

---

## CHAPTER 2: LITERATURE SURVEY & FEASIBILITY STUDY

### 2.1 Existing Security Systems vs. CloudShield

| Feature | Enterprise Commercial SIEM (Splunk, QRadar) | Basic Open-Source Logging (ELK Stack) | CloudShield Platform |
|---|---|---|---|
| **Cost** | ₹10,00,000+ / year | Free software, high server cost | **Freemium (₹0 Free Tier)** |
| **Setup Complexity** | Weeks / Requires certified experts | Moderate to high setup overhead | **Zero-config / 1-click start** |
| **Multi-Tenancy** | Complex enterprise add-on | Single-tenant by default | **Native Multi-Tenant Architecture** |
| **Real-Time Alerting** | Yes (batch/stream) | Requires custom ElastAlert setup | **Automated Zero-Latency Rules** |
| **AI Anomaly Detection** | Expensive add-on licenses | Requires ML pipeline engineering | **Built-in Behavioral Scoring** |
| **Live Event Ingestion** | Complex enterprise add-on | Requires Logstash / Filebeat | **Native REST Gateway & Terminal Agent** |

### 2.2 Feasibility Analysis
* **Technical Feasibility:** The project utilizes standard, robust technologies—Python 3.13, FastAPI (ASGI), SQLite, and Docker—all of which are open-source and well-supported across Windows and Linux.
* **Operational Feasibility:** The user interface is built using standard HTML5/CSS3/JavaScript, requiring zero special browser plugins and providing live, real-time security telemetry.
* **Economic Feasibility:** The system requires minimal system resources (operates smoothly on 4 GB RAM) and has zero proprietary licensing costs.

---

## CHAPTER 3: SOFTWARE REQUIREMENT SPECIFICATION (SRS)

### 3.1 Functional Requirements
* **FR-1 (Tenant Registration & Partitioning):** The system must register organizations with unique IDs and enforce data separation.
* **FR-2 (User Authentication & Cryptography):** Passwords must be hashed using SHA-256 before storage.
* **FR-3 (Real-Time Ingestion Gateway):** External servers, cloud instances, and client agents must be able to push live security events via authenticated REST API (`POST /api/v1/events`) using tenant API keys.
* **FR-4 (Threat Detection):** The engine must detect Brute Force attacks ($\ge 3$ failures in 5 min) and DDoS traffic surges ($\ge 15$ req in 60s).
* **FR-5 (AI Behavioral Scoring):** The system must compute anomaly scores (0.0 to 1.0) and assign risk ratings (LOW to CRITICAL).
* **FR-6 (Subscription Feature Gating):** Free-tier tenants calling Pro endpoints must receive an HTTP 403 Forbidden response.
* **FR-7 (Live Mitigation):** Administrators must be able to resolve active incidents, transitioning their status from `ACTIVE` to `RESOLVED`.

### 3.2 Non-Functional Requirements
* **Performance:** Real-time threat evaluation must execute in $< 50$ milliseconds per log event.
* **Security:** All database queries must be strictly parameterized to eliminate SQL Injection.
* **Availability:** Asynchronous non-blocking architecture (FastAPI + Uvicorn) ensuring server responsiveness during traffic spikes.
* **Portability:** Containerized with Docker to run on any host operating system or cloud provider.

### 3.3 Hardware & Software Specifications
* **Hardware:** Intel Core i3 / AMD Ryzen 3+, 4 GB RAM, 500 MB Storage.
* **Software:** Python 3.13+, FastAPI, Uvicorn, SQLite, Docker, Modern Web Browser.

---

## CHAPTER 4: SYSTEM DESIGN & ARCHITECTURE

### 4.1 System Architectural Design

```text
       ┌─────────────────────────────────────────────────────────┐
       │             Client Browsers / Remote Servers            │
       └────────────────────────────┬────────────────────────────┘
                                    │ HTTPS (JSON / REST API)
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │             FastAPI Microservice Gateway                │
       │           (ASGI High-Concurrency Controller)            │
       └──────────────┬───────────────────────────┬──────────────┘
                      │                           │
                      ▼                           ▼
       ┌────────────────────────────┐ ┌───────────────────────────┐
       │ Multi-Tenant Security Guard│ │ Threat Detection Engine   │
       │ (Feature-Gating & Context) │ │ • 4 Real-Time Rules       │
       │ (Free vs. Pro Plans)       │ │ • ML Anomaly Scorer       │
       └──────────────┬─────────────┘ └───────────┬───────────────┘
                      │                           │
                      └─────────────┬─────────────┘
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │        Relational Database (cloud_security.db)          │
       │      [companies, plans, subscriptions, logs, alerts]    │
       └────────────────────────────┬────────────────────────────┘
                                    │ Non-Blocking Polling (3s)
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │             Web SOC Dashboard Interface                 │
       │         (Real-time Threat Feed & Mitigation Desk)       │
       └─────────────────────────────────────────────────────────┘
```

### 4.2 Database Schema Specification

```text
 ┌──────────────────────┐          ┌──────────────────────┐
 │      companies       │          │        plans         │
 ├──────────────────────┤          ├──────────────────────┤
 │ id (PK)              │          │ id (PK)              │
 │ name (UNIQUE)        │          │ name (FREE/PRO)      │
 │ api_key              │          │ price                │
 │ created_at           │          │ features             │
 └──────────┬───────────┘          └──────────┬───────────┘
            │                                 │
            ├─────────────────┐               │
            ▼                 ▼               ▼
 ┌──────────────────────┐  ┌──────────────────────┐
 │    activity_logs     │  │    subscriptions     │
 ├──────────────────────┤  ├──────────────────────┤
 │ id (PK)              │  │ id (PK)              │
 │ company_id (FK)      │  │ company_id (FK)      │
 │ action               │  │ plan_id (FK)         │
 │ ip_address           │  │ status (ACTIVE)      │
 │ status               │  │ start_date / end_date│
 └──────────────────────┘  └──────────────────────┘
```

---

## CHAPTER 5: IMPLEMENTATION DETAILS & ALGORITHMS

### 5.1 Brute Force Detection Algorithm
```python
# Sliding-window Brute Force Algorithm:
SELECT ip_address, username, COUNT(*) as failed_count 
FROM activity_logs 
WHERE company_id = :company_id
  AND action = 'LOGIN_FAILED' 
  AND timestamp >= datetime('now', '-5 minutes')
GROUP BY ip_address, username
HAVING failed_count >= 3;

# IF match found:
Trigger create_security_alert(
    alert_type="BRUTE_FORCE_ATTACK",
    severity="CRITICAL",
    mitigation="Auto-block IP & Enforce CAPTCHA"
)
```

### 5.2 AI Behavioral Anomaly Scoring Algorithm
```python
# Multidimensional Anomaly Scoring:
score = 0.0
IF velocity > 30 req/min:      score += 0.35
IF failure_ratio >= 0.70:       score += 0.35
IF access_hour in [1, 2, 3, 4]: score += 0.15
IF unique_ips >= 3:             score += 0.15

score = min(score, 1.0)
IF score >= 0.70: Risk = "CRITICAL"
ELIF score >= 0.45: Risk = "HIGH"
ELIF score >= 0.25: Risk = "MEDIUM"
ELSE: Risk = "LOW"
```

---

## CHAPTER 6: SOFTWARE TESTING & RESULTS

### 6.1 Automated Pytest Execution Results
Automated unit and integration testing was executed using `pytest` across all modules:

```text
============================= test session starts =============================
platform win32 -- Python 3.13.7, pytest-9.0.2
collected 6 items

tests/test_cloudshield.py::test_company_listing_and_seeding PASSED       [ 16%]
tests/test_cloudshield.py::test_password_hashing_and_user_creation PASSED [ 33%]
tests/test_cloudshield.py::test_multi_tenant_data_isolation PASSED       [ 50%]
tests/test_cloudshield.py::test_brute_force_rule_detection PASSED        [ 66%]
tests/test_cloudshield.py::test_freemium_subscription_upgrade PASSED     [ 83%]
tests/test_cloudshield.py::test_ai_anomaly_scoring_model PASSED          [100%]

============================== 6 passed in 0.40s ==============================
```

### 6.2 Test Cases Execution Matrix

| Test ID | Test Scenario | Expected Outcome | Actual Result | Status |
|---|---|---|---|:---:|
| **TC-01** | Multi-tenant company listing | Seeded companies retrieved with active plans | Matches seeded records | **PASS** |
| **TC-02** | User credential hashing | SHA-256 creates 64-char hex digest | Stored hash matches standard | **PASS** |
| **TC-03** | Tenant data isolation | Company 1 cannot access Company 2 logs | 100% data partition confirmed | **PASS** |
| **TC-04** | Brute force detection | 3 failed logins triggers CRITICAL alert | Critical alert created instantly | **PASS** |
| **TC-05** | Freemium feature gating | Free tenant receives 403 on Pro AI route | HTTP 403 Forbidden received | **PASS** |
| **TC-06** | Subscription upgrade flow | Upgrading to Pro unlocks AI endpoint | Endpoint returns HTTP 200 OK | **PASS** |

---

## CHAPTER 7: CONCLUSION & FUTURE SCOPE

### 7.1 Summary of Contributions
**CloudShield** successfully bridges academic computer science theory with industry-grade software engineering:
1. Demonstrated practical implementation of **Cloud Multi-Tenancy** and **Security as a Service (SECaaS)**.
2. Built a functional **Freemium Business Model** powered by backend API feature gating.
3. Implemented a zero-latency **Automated Threat Detection Engine** combined with **AI Behavioral Deviation Scoring**.
4. Packaged the entire platform into a containerized, cloud-deployable architecture.

### 7.2 Future Enhancements
* **Automated Firewall Rule Enforcement:** Automatically triggering cloud APIs (AWS Security Groups / Cloudflare WAF) to block hostile IPs.
* **Real-Time Notification Dispatch:** Integrating SMS (Twilio) and Email (SendGrid) alerting webhooks.
* **Cloud Production Deployment:** Migrating from SQLite to an Amazon Aurora distributed PostgreSQL database cluster.

---

## REFERENCES & BIBLIOGRAPHY

1. Stallings, W. (2018). *Cryptography and Network Security: Principles and Practice*. Pearson Education.
2. Chuvakin, A., Schmidt, K. & Phillips, C. (2012). *Security Information and Event Management (SIEM) Implementation*. McGraw-Hill.
3. Tiangolo, S. (2024). *FastAPI: High performance, easy to learn, fast to code*. Official Documentation, https://fastapi.tiangolo.com/
4. Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). *Isolation Forest*. IEEE International Conference on Data Mining (ICDM).
5. Docker Inc. (2024). *Docker Documentation: Containerization and Orchestration*, https://docs.docker.com/
