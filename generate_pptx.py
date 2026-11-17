from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN

def create_deck():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    DARK_BG = RGBColor(10, 15, 29)
    CYAN = RGBColor(0, 242, 254)
    WHITE = RGBColor(255, 255, 255)
    MUTED = RGBColor(156, 163, 175)
    CARD_BG = RGBColor(17, 24, 39)
    ACCENT_PURPLE = RGBColor(99, 102, 241)

    slides_content = [
        {
            "type": "title",
            "title": "CLOUDSHIELD",
            "subtitle": "Intelligent Cloud Security Monitoring & Threat Detection Platform",
            "tagline": "A Freemium, Multi-Tenant Cloud-Based Cybersecurity SaaS Platform",
            "presenter": "Presented by: Veeresh\nDegree: Bachelor of Computer Applications (BCA)\nInstitution: KLE Technological University\nAcademic Year: 2026 – 2027"
        },
        {
            "type": "content",
            "category": "PROBLEM BACKGROUND",
            "title": "The Security Challenge in Modern Cloud Applications",
            "points": [
                "Modern organizations rely on cloud apps, web microservices, and distributed REST APIs.",
                "Every digital transaction produces continuous audit logs (logins, API calls, data requests).",
                "Critical Problem: Manual log inspection is impossible due to massive log volume.",
                "SME Dilemma: Commercial enterprise SIEM tools (Splunk, IBM QRadar) require heavy hardware and cost millions of rupees.",
                "The Threat: Without automated detection, Brute Force attacks, DDoS surges, and account takeovers go unnoticed until damage is done."
            ]
        },
        {
            "type": "content",
            "category": "PROPOSED SOLUTION",
            "title": "CloudShield: Security as a Service (SECaaS)",
            "points": [
                "Centralized Cloud SIEM: Ingests, normalizes, and analyzes security logs in real time.",
                "Multi-Tenant Cloud Architecture: Multiple client companies share a single scalable cloud backend while maintaining 100% logical data isolation.",
                "Zero-Latency Rule Engine: Detects attack patterns (Brute Force, DDoS, Privilege Escalation) within milliseconds.",
                "AI Behavioral Anomaly Detection: Machine learning baseline model scores deviations that strict rules miss.",
                "Freemium SaaS Model: Free essential security (₹0) for startups, with seamless paid tier upgrades for advanced AI intelligence."
            ]
        },
        {
            "type": "content",
            "category": "SYSTEM OBJECTIVES",
            "title": "Key Project Objectives",
            "points": [
                "1. Build Multi-Tenant Architecture: Secure multi-company tenancy with clean database partitioning by company_id.",
                "2. Real-Time Audit Ingestion: Standardize incoming event metadata (Action, IP, User, Timestamp, Status).",
                "3. Sliding-Window Rule Engine: Implement automated SQL algorithms that trigger instant critical alerts.",
                "4. AI Behavioral Anomaly Scorer: Multi-dimensional deviation tracking (Velocity, Failure Ratio, Off-Hours, Geo-IP).",
                "5. Backend Feature-Gating Engine: Strictly restrict premium endpoints behind subscription status (Free vs. Pro).",
                "6. Cyber SOC Dashboard: High-visibility dark theme interface updating asynchronously every 3 seconds."
            ]
        },
        {
            "type": "content",
            "category": "SYSTEM ARCHITECTURE",
            "title": "End-to-End System Architecture & Data Flow",
            "points": [
                "1. Client Layer: Web applications and remote servers push event payloads over HTTPS to our FastAPI Gateway.",
                "2. Authentication & Validation: Pydantic schemas validate input; SHA-256 cryptographic hashing protects credentials.",
                "3. Detection & Storage: Incoming logs are saved to SQLite and evaluated against sliding-window detection rules simultaneously.",
                "4. Intelligence Layer: Pro-tier requests pass through the Isolation Anomaly Scoring Engine.",
                "5. SOC Dashboard: Vanilla JS polls the backend asynchronously every 3 seconds to update alert cards and metrics live without page reload."
            ]
        },
        {
            "type": "content",
            "category": "CLOUD ARCHITECTURE",
            "title": "Multi-Tenancy & Logical Data Isolation",
            "points": [
                "What is Multi-Tenancy? One shared software infrastructure serves multiple customer organizations (tenants).",
                "Tenant Partitioning: Every database table (activity_logs, security_alerts, users) carries a mandatory company_id.",
                "Strict Data Privacy: All database queries enforce 'WHERE company_id = ?'. Company A can never query or view Company B's records.",
                "Independent API Keys: Each tenant receives a distinct cryptographically generated API key for log ingestion.",
                "Scalability: New companies can register and begin monitoring instantly without provisioning separate server hardware."
            ]
        },
        {
            "type": "content",
            "category": "THREAT DETECTION",
            "title": "Automated Rule-Based Detection Engine",
            "points": [
                "Rule 1 - Brute Force Attack (CRITICAL): Detects >= 3 failed login attempts from same IP/username in 5 mins -> Recommends IP Block & CAPTCHA.",
                "Rule 2 - DDoS Traffic Surge (HIGH): Detects >= 15 HTTP requests in 60 seconds from a single IP -> Recommends 1 req/sec rate limit & WAF challenge.",
                "Rule 3 - Privilege Escalation (HIGH): Flags unauthorized attempts to access restricted admin endpoints -> Recommends token revocation.",
                "Rule 4 - Anomalous Proxy / Tor Nodes (MEDIUM): Matches incoming traffic against known Tor Exit Node subnets (185.220.*) -> Recommends mandatory 2FA.",
                "Zero-Latency: Evaluated immediately upon log insertion; no batch delays."
            ]
        },
        {
            "type": "content",
            "category": "AI & MACHINE LEARNING",
            "title": "Machine Learning Behavioral Anomaly Detection",
            "points": [
                "Why ML? Attackers can deliberately stay beneath rule thresholds (e.g., slow attacks or off-hours exfiltration).",
                "Multi-Dimensional Model: Evaluates 4 distinct behavioral vectors:",
                "  • Request Velocity Spike: Sudden burst compared to normal baseline traffic.",
                "  • Failure Concentration Ratio: High percentage of failed operations.",
                "  • Off-Hours Access: Activity occurring between 01:00 AM - 05:00 AM.",
                "  • Geo-IP Dispersion: Account accessed from multiple distant IPs simultaneously.",
                "Output: Computes a Deviation Score (0.0 to 1.0), assigns Risk Level (CRITICAL/HIGH/MEDIUM), and details mitigation."
            ]
        },
        {
            "type": "content",
            "category": "BUSINESS MODEL",
            "title": "Freemium SaaS Model & Feature Gating",
            "points": [
                "Tier 1 - FREE PLAN (₹0/month): Essential monitoring, rule-based threat detection, 7-day retention, standard SOC dashboard.",
                "Tier 2 - PROFESSIONAL (₹999/month): Unlocks AI/ML Anomaly Detection, velocity deviation tracking, 30-day retention, email alerts.",
                "Tier 3 - ENTERPRISE (Custom): Dedicated cloud pod, custom threat rules, unlimited retention, 24/7 priority support.",
                "Backend Feature Guard: Protected endpoint /api/pro/ai-anomalies returns HTTP 403 Forbidden on Free plan.",
                "Live Sandbox Upgrade: Demonstrates live payment checkout simulation that updates the company plan and unlocks AI features instantaneously."
            ]
        },
        {
            "type": "content",
            "category": "TECHNOLOGY STACK",
            "title": "Technology Stack & Engineering Decisions",
            "points": [
                "Backend Framework: FastAPI (Python 3.13) - Asynchronous, high-performance, automatic OpenAPI documentation.",
                "Web Server: Uvicorn (ASGI) - Handles concurrent network connections with zero blocking.",
                "Database: SQLite (cloud_security.db) - Lightweight, serverless relational database with parameterized queries.",
                "Frontend: HTML5, CSS3 (Cyberpunk SOC Theme), Vanilla JavaScript (ES6+) - 3-second asynchronous polling.",
                "Containerization: Docker & Docker Compose - Microservice architecture ready for AWS EC2 / Azure deployment.",
                "Security & Cryptography: Hashlib (SHA-256) password hashing, Pydantic data validation."
            ]
        },
        {
            "type": "content",
            "category": "PROJECT DEMONSTRATION",
            "title": "Academic Viva Demonstration Sequence",
            "points": [
                "1. Baseline SOC: Show clean dashboard with 0 active threats for Acme Cloud Systems (Free Plan).",
                "2. Live Event Ingestion: Use the Real-Time Ingestion Gateway (or agent.py) to stream real HTTP traffic live.",
                "3. Live Threat Detection: Transmit Brute Force & DDoS attacks; watch real-time Red Alerts appear in < 15ms.",
                "4. SOC Incident Mitigation: Click 'Mitigate & Resolve' to transition alert from ACTIVE to RESOLVED.",
                "5. Compliance Export: Download ISO 27001-ready CSV audit logs & JSON incident reports in 1 click.",
                "6. Freemium Upgrade & AI Unlock: Upgrade to Pro (₹999) to unlock Machine Learning Behavioral Anomaly Scoring!"
            ]
        },
        {
            "type": "content",
            "category": "CONCLUSION & FUTURE SCOPE",
            "title": "Conclusion & Future Enhancements",
            "points": [
                "Academic Value: Successfully proves integration of Cloud Computing (Multi-Tenancy, SaaS, Docker) with Cybersecurity (SIEM, Threat Rules, AI Detection).",
                "Practical Impact: Delivers an affordable, enterprise-style security monitoring platform for modern organizations.",
                "Future Scope 1: Integration with real SMS/Email webhook alerts (Twilio / SendGrid).",
                "Future Scope 2: Automated firewall rule generation (iptables / AWS Security Groups).",
                "Future Scope 3: Cloud production deployment on AWS ECS with distributed PostgreSQL."
            ]
        }
    ]

    for item in slides_content:
        slide = prs.slides.add_slide(blank_layout)

        # Background card
        bg_shape = slide.shapes.add_shape(1, 0, 0, Inches(13.333), Inches(7.5))
        bg_shape.fill.solid()
        bg_shape.fill.fore_color.rgb = DARK_BG
        bg_shape.line.color.rgb = DARK_BG

        if item["type"] == "title":
            card = slide.shapes.add_shape(1, Inches(1.5), Inches(1.0), Inches(10.333), Inches(5.5))
            card.fill.solid()
            card.fill.fore_color.rgb = CARD_BG
            card.line.color.rgb = CYAN
            card.line.width = Pt(2)

            tx_box = slide.shapes.add_textbox(Inches(1.8), Inches(1.3), Inches(9.7), Inches(4.8))
            tf = tx_box.text_frame
            tf.word_wrap = True

            p0 = tf.paragraphs[0]
            p0.text = item["title"]
            p0.font.size = Pt(44)
            p0.font.bold = True
            p0.font.color.rgb = CYAN
            p0.alignment = PP_ALIGN.CENTER

            p1 = tf.add_paragraph()
            p1.text = item["subtitle"]
            p1.font.size = Pt(20)
            p1.font.bold = True
            p1.font.color.rgb = WHITE
            p1.alignment = PP_ALIGN.CENTER

            p2 = tf.add_paragraph()
            p2.text = item["tagline"]
            p2.font.size = Pt(14)
            p2.font.italic = True
            p2.font.color.rgb = ACCENT_PURPLE
            p2.alignment = PP_ALIGN.CENTER
            p2.space_after = Pt(24)

            p3 = tf.add_paragraph()
            p3.text = item["presenter"]
            p3.font.size = Pt(13)
            p3.font.color.rgb = MUTED
            p3.alignment = PP_ALIGN.CENTER

        else:
            header_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(1.2))
            htf = header_box.text_frame
            htf.word_wrap = True

            cp = htf.paragraphs[0]
            cp.text = item["category"]
            cp.font.size = Pt(11)
            cp.font.bold = True
            cp.font.color.rgb = CYAN

            tp = htf.add_paragraph()
            tp.text = item["title"]
            tp.font.size = Pt(24)
            tp.font.bold = True
            tp.font.color.rgb = WHITE

            content_card = slide.shapes.add_shape(1, Inches(0.8), Inches(1.8), Inches(11.7), Inches(5.0))
            content_card.fill.solid()
            content_card.fill.fore_color.rgb = CARD_BG
            content_card.line.color.rgb = RGBColor(30, 41, 59)
            content_card.line.width = Pt(1)

            tx_box = slide.shapes.add_textbox(Inches(1.2), Inches(2.1), Inches(10.9), Inches(4.4))
            tf = tx_box.text_frame
            tf.word_wrap = True

            for idx, pt in enumerate(item["points"]):
                p = tf.paragraphs[0] if idx == 0 else tf.add_paragraph()
                p.text = pt
                p.font.size = Pt(14)
                p.font.color.rgb = WHITE if idx % 2 == 0 else RGBColor(226, 232, 240)
                p.space_after = Pt(12)
                p.level = 1 if pt.strip().startswith("•") else 0

    output_path = r"c:\Users\veere\OneDrive\Desktop\mini_project\CloudShield_Seminar_Presentation.pptx"
    prs.save(output_path)
    print(f"Presentation generated successfully: {output_path}")

if __name__ == "__main__":
    create_deck()
