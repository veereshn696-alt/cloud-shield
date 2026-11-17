import sqlite3
from database import get_db_connection, create_security_alert

def evaluate_security_rules(company_id: int = 1, latest_ip: str = None, latest_username: str = None):
    """
    Evaluates real-time security rules against activity logs for a specific tenant company.
    Triggers automated security alerts when attack patterns are detected.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    alerts_triggered = []

    # Rule 1: Brute Force Attack Detection
    # Count failed logins in last 5 minutes from same IP or username within the company
    cursor.execute('''
        SELECT ip_address, username, COUNT(*) as failed_count 
        FROM activity_logs 
        WHERE company_id = ?
          AND action = 'LOGIN_FAILED' 
          AND timestamp >= datetime('now', '-5 minutes')
        GROUP BY ip_address, username
        HAVING failed_count >= 3
    ''', (company_id,))
    brute_force_cases = cursor.fetchall()
    for case in brute_force_cases:
        ip = case['ip_address']
        user = case['username']
        cnt = case['failed_count']
        msg = f"Brute Force Attack Detected: {cnt} failed login attempts for user '{user}' from IP {ip}."
        alert_id = create_security_alert(
            alert_type="BRUTE_FORCE_ATTACK",
            severity="CRITICAL",
            source_ip=ip,
            target_user=user,
            message=msg,
            mitigation_action="Auto-block IP & Enforce CAPTCHA",
            company_id=company_id
        )
        if alert_id:
            alerts_triggered.append({"type": "BRUTE_FORCE_ATTACK", "ip": ip, "user": user})

    # Rule 2: DDoS / High Request Rate Surge Detection
    # Count total requests in last 1 minute per IP
    cursor.execute('''
        SELECT ip_address, COUNT(*) as req_count 
        FROM activity_logs 
        WHERE company_id = ?
          AND timestamp >= datetime('now', '-1 minute')
        GROUP BY ip_address
        HAVING req_count >= 15
    ''', (company_id,))
    ddos_cases = cursor.fetchall()
    for case in ddos_cases:
        ip = case['ip_address']
        cnt = case['req_count']
        msg = f"DDoS / Traffic Rate Surge Detected: {cnt} requests in 60s from IP {ip}."
        alert_id = create_security_alert(
            alert_type="DDOS_RATE_SPIKE",
            severity="HIGH",
            source_ip=ip,
            target_user="API Gateway",
            message=msg,
            mitigation_action="Rate-limit IP to 1 req/sec & Challenge WAF",
            company_id=company_id
        )
        if alert_id:
            alerts_triggered.append({"type": "DDOS_RATE_SPIKE", "ip": ip})

    # Rule 3: Unauthorized Access Violation
    cursor.execute('''
        SELECT ip_address, username, details 
        FROM activity_logs 
        WHERE company_id = ?
          AND action = 'UNAUTHORIZED_ACCESS'
          AND timestamp >= datetime('now', '-5 minutes')
    ''', (company_id,))
    unauth_cases = cursor.fetchall()
    for case in unauth_cases:
        ip = case['ip_address']
        user = case['username']
        details = case['details']
        msg = f"Unauthorized Access Attempt: User '{user}' attempted to access restricted endpoint ({details})."
        alert_id = create_security_alert(
            alert_type="UNAUTHORIZED_PRIVILEGE_ACCESS",
            severity="HIGH",
            source_ip=ip,
            target_user=user,
            message=msg,
            mitigation_action="Revoke Token & Require Re-Authentication",
            company_id=company_id
        )
        if alert_id:
            alerts_triggered.append({"type": "UNAUTHORIZED_PRIVILEGE_ACCESS", "ip": ip, "user": user})

    # Rule 4: Anomalous Location / Tor Exit Node IP
    cursor.execute('''
        SELECT ip_address, username, details
        FROM activity_logs
        WHERE company_id = ?
          AND (ip_address LIKE '185.220.%' OR ip_address LIKE '198.51.100.%' OR details LIKE '%Suspicious IP%')
          AND timestamp >= datetime('now', '-5 minutes')
    ''', (company_id,))
    anom_cases = cursor.fetchall()
    for case in anom_cases:
        ip = case['ip_address']
        user = case['username']
        msg = f"Anomalous Geo Location / Known Malicious Proxy IP detected: {ip} for user '{user}'."
        alert_id = create_security_alert(
            alert_type="ANOMALOUS_LOCATION",
            severity="MEDIUM",
            source_ip=ip,
            target_user=user,
            message=msg,
            mitigation_action="Trigger 2FA Verification",
            company_id=company_id
        )
        if alert_id:
            alerts_triggered.append({"type": "ANOMALOUS_LOCATION", "ip": ip, "user": user})

    conn.close()
    return alerts_triggered
