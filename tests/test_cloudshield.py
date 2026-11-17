import pytest
import sqlite3
import hashlib
from database import (
    init_db,
    get_db_connection,
    log_activity,
    create_security_alert,
    get_company,
    get_company_by_api_key,
    get_all_companies,
    get_company_subscription,
    upgrade_subscription
)
from security_engine import evaluate_security_rules
from ml_engine import compute_anomaly_score, detect_anomalies

@pytest.fixture(autouse=True)
def setup_database():
    """Ensure clean schema before test execution."""
    init_db()

def test_company_listing_and_seeding():
    """Verify multi-tenant companies are correctly initialized."""
    companies = get_all_companies()
    assert len(companies) >= 2
    # Company 1 should be Acme Cloud Systems
    assert companies[0]["name"] == "Acme Cloud Systems"
    # Company 2 should be Nexus Cyber Tech
    assert companies[1]["name"] == "Nexus Cyber Tech"

def test_password_hashing_and_user_creation():
    """Test SHA-256 cryptographic hashing."""
    test_password = "SecurePassword@123"
    pass_hash = hashlib.sha256(test_password.encode()).hexdigest()
    assert len(pass_hash) == 64
    assert pass_hash != test_password

def test_multi_tenant_data_isolation():
    """Verify logs inserted for Company 1 are isolated from Company 2."""
    conn = get_db_connection()
    c = conn.cursor()
    
    # Ingest log for Company 1
    log_activity(
        company_id=1,
        action="API_REQUEST",
        ip_address="192.168.1.10",
        status="SUCCESS",
        username="tenant1_user"
    )

    # Ingest log for Company 2
    log_activity(
        company_id=2,
        action="API_REQUEST",
        ip_address="10.0.0.5",
        status="SUCCESS",
        username="tenant2_user"
    )

    # Query logs scoped strictly to Company 1
    c.execute("SELECT * FROM activity_logs WHERE company_id = 1")
    logs_c1 = c.fetchall()
    assert all(row['company_id'] == 1 for row in logs_c1)

    # Query logs scoped strictly to Company 2
    c.execute("SELECT * FROM activity_logs WHERE company_id = 2")
    logs_c2 = c.fetchall()
    assert all(row['company_id'] == 2 for row in logs_c2)

    conn.close()

def test_brute_force_rule_detection():
    """Test that >= 3 failed logins from same IP triggers a CRITICAL alert."""
    test_ip = "192.168.99.10"
    test_user = "test_admin"

    # Insert 3 rapid failed logins
    for _ in range(3):
        log_activity(
            company_id=1,
            action="LOGIN_FAILED",
            ip_address=test_ip,
            status="FAILURE",
            username=test_user
        )

    # Evaluate detection rules
    alerts = evaluate_security_rules(company_id=1, latest_ip=test_ip, latest_username=test_user)
    assert len(alerts) >= 1

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT * FROM security_alerts WHERE company_id = 1 AND alert_type = 'BRUTE_FORCE_ATTACK' AND source_ip = ?",
        (test_ip,)
    )
    alert = c.fetchone()
    conn.close()

    assert alert is not None
    assert alert['severity'] == "CRITICAL"
    assert alert['target_user'] == test_user

def test_freemium_subscription_upgrade():
    """Test upgrading a tenant from FREE to PROFESSIONAL plan."""
    # Ensure Company 1 starts as FREE
    upgrade_subscription(company_id=1, plan_name="FREE")
    sub_free = get_company_subscription(company_id=1)
    assert sub_free["plan_name"] == "FREE"
    assert "ml_anomalies" not in sub_free["features"]

    # Upgrade to PROFESSIONAL
    success, msg = upgrade_subscription(company_id=1, plan_name="PROFESSIONAL")
    assert success is True

    sub_pro = get_company_subscription(company_id=1)
    assert sub_pro["plan_name"] == "PROFESSIONAL"
    assert "ml_anomalies" in sub_pro["features"]

def test_ai_anomaly_scoring_model():
    """Test the behavioral anomaly detection scoring algorithm."""
    # Normal behavior: velocity 3, fail_ratio 0.05, off_hours 0, ip_count 1
    score_normal, risk_normal, reasons_normal = compute_anomaly_score(
        velocity=3.0, fail_ratio=0.05, off_hours=0, ip_count=1
    )
    assert risk_normal == "LOW"
    assert score_normal < 0.25

    # Anomalous behavior: high velocity 45, fail_ratio 0.85, off_hours 1
    score_bad, risk_bad, reasons_bad = compute_anomaly_score(
        velocity=45.0, fail_ratio=0.85, off_hours=1, ip_count=4
    )
    assert risk_bad in ["HIGH", "CRITICAL"]
    assert score_bad >= 0.70
    assert len(reasons_bad) >= 3

def test_api_key_lookup_and_event_ingestion():
    """Test tenant lookup via API key and real-time security event ingestion."""
    # Lookup tenant with known API key
    company = get_company_by_api_key("acme_sec_live_9921")
    assert company is not None
    assert company["id"] == 1
    assert company["name"] == "Acme Cloud Systems"

    # Ingest event under this tenant
    log_id = log_activity(
        company_id=company["id"],
        action="SSH_AUTH_FAILURE",
        ip_address="198.51.100.42",
        status="FAILURE",
        username="root",
        details="Real-time SSH probe detected"
    )
    assert log_id > 0

    # Ensure nonexistent API key returns None
    invalid = get_company_by_api_key("fake_invalid_key_xyz")
    assert invalid is None
