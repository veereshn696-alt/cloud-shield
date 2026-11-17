import os
import io
import csv
import hashlib
import sqlite3
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, status, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from database import (
    init_db,
    get_db_connection,
    log_activity,
    create_security_alert,
    get_company,
    get_company_by_api_key,
    get_all_companies,
    get_company_subscription,
    get_plans,
    upgrade_subscription,
    register_new_company
)
from security_engine import evaluate_security_rules
from ml_engine import detect_anomalies

app = FastAPI(
    title="CloudShield - Freemium Cloud Cybersecurity Platform",
    description="Multi-Tenant SIEM with AI Anomaly Detection & Subscription Management",
    version="2.0.0"
)

# Initialize database on startup
@app.on_event("startup")
def startup_event():
    init_db()

# Request schemas
class LoginRequest(BaseModel):
    username: str
    password: str
    company_id: Optional[int] = 1

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    company_id: Optional[int] = 1

class UpgradeRequest(BaseModel):
    company_id: int
    plan_name: str
    payment_method: Optional[str] = "SANDBOX_MOCK_UPI"

class CompanyRegisterRequest(BaseModel):
    company_name: str
    domain: Optional[str] = "cloudapp.io"
    admin_username: str
    admin_email: str
    password: str

class EventIngestRequest(BaseModel):
    api_key: Optional[str] = None
    action: str
    username: Optional[str] = "anonymous"
    ip_address: Optional[str] = None
    status: Optional[str] = "SUCCESS"
    details: Optional[str] = ""
    user_agent: Optional[str] = None

# Helper to get client IP
def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0]
    return request.client.host if request.client else "127.0.0.1"

# --- MULTI-TENANT & SUBSCRIPTION ENDPOINTS ---

@app.get("/api/companies")
async def list_companies():
    """Lists all tenant companies and their active plans."""
    return {"companies": get_all_companies()}

@app.post("/api/companies/register")
async def register_company_endpoint(req: CompanyRegisterRequest):
    """
    Onboards a brand new tenant organization with their own company_id,
    generates an API key, creates their admin user, and sets them to the FREE plan.
    """
    pass_hash = hashlib.sha256(req.password.encode()).hexdigest()
    success, result = register_new_company(
        company_name=req.company_name,
        domain=req.domain,
        admin_username=req.admin_username,
        admin_email=req.admin_email,
        password_hash=pass_hash
    )
    if not success:
        raise HTTPException(status_code=400, detail=result)
    
    return {
        "status": "success",
        "message": f"Organization '{req.company_name}' successfully created!",
        "tenant_data": result
    }

@app.get("/api/companies/{company_id}")
async def get_company_details(company_id: int):
    comp = get_company(company_id)
    if not comp:
        raise HTTPException(status_code=404, detail="Company not found")
    sub = get_company_subscription(company_id)
    comp["subscription"] = sub
    return comp

@app.get("/api/plans")
async def list_plans():
    """Lists available Freemium and Premium subscription tiers."""
    return {"plans": get_plans()}

@app.post("/api/subscriptions/upgrade")
async def process_upgrade(req: UpgradeRequest):
    """
    Simulates real-time subscription upgrade with sandbox payment verification.
    Unlocks AI Anomaly Detection and Pro features instantly.
    """
    success, msg = upgrade_subscription(req.company_id, req.plan_name)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    
    # Log the administrative subscription event
    log_activity(
        company_id=req.company_id,
        action="SUBSCRIPTION_UPGRADED",
        ip_address="127.0.0.1",
        status="SUCCESS",
        username="admin",
        details=f"Tenant upgraded to {req.plan_name.upper()} via {req.payment_method}"
    )

    return {
        "status": "success",
        "message": msg,
        "company_id": req.company_id,
        "new_plan": req.plan_name.upper(),
        "unlocked_features": ["ml_anomalies", "advanced_analytics", "email_alerts"]
    }

# --- PRO FEATURE-GATED ENDPOINT: AI ANOMALY DETECTION ---

@app.get("/api/pro/ai-anomalies")
async def get_ai_anomalies(company_id: int = Query(1)):
    """
    FEATURE-GATED ENDPOINT:
    Requires PROFESSIONAL or ENTERPRISE subscription.
    Free tier tenants receive an HTTP 403 / Feature-Locked response.
    """
    sub = get_company_subscription(company_id)
    plan_name = sub.get("plan_name", "FREE").upper()

    if plan_name not in ["PROFESSIONAL", "ENTERPRISE"]:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "locked": True,
                "current_plan": plan_name,
                "required_plan": "PROFESSIONAL",
                "message": "🔒 Premium Feature: AI & Machine Learning Anomaly Detection is locked. Upgrade to the Professional Plan (₹999/mo) to unlock real-time behavioral deviation scoring.",
                "preview_features": [
                    "Multi-Dimensional Isolation Scoring",
                    "Behavioral Velocity Deviation Tracking",
                    "Off-Hours Geo-Anomaly Analysis",
                    "Automated Threat Quarantine"
                ]
            }
        )

    # If unlocked, run the AI Anomaly Detection Engine
    results = detect_anomalies(company_id=company_id)
    return {
        "locked": False,
        "company_id": company_id,
        "plan": plan_name,
        "ai_results": results
    }

# --- AUTH ENDPOINTS ---

@app.post("/api/auth/login")
async def login(req: LoginRequest, request: Request):
    ip_addr = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "WebBrowser")
    cid = req.company_id or 1
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND company_id = ?", (req.username, cid))
    user = cursor.fetchone()
    conn.close()

    pass_hash = hashlib.sha256(req.password.encode()).hexdigest()

    if user and user['password_hash'] == pass_hash:
        log_activity(
            company_id=cid,
            action="LOGIN_SUCCESS",
            ip_address=ip_addr,
            status="SUCCESS",
            username=req.username,
            user_agent=user_agent,
            details=f"User '{req.username}' logged in successfully"
        )
        evaluate_security_rules(company_id=cid, latest_ip=ip_addr, latest_username=req.username)
        return {
            "status": "success",
            "message": "Login successful",
            "username": user['username'],
            "role": user['role'],
            "company_id": cid
        }
    else:
        log_activity(
            company_id=cid,
            action="LOGIN_FAILED",
            ip_address=ip_addr,
            status="FAILURE",
            username=req.username,
            user_agent=user_agent,
            details=f"Invalid password for username '{req.username}'"
        )
        alerts = evaluate_security_rules(company_id=cid, latest_ip=ip_addr, latest_username=req.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "Invalid username or password",
                "alerts_triggered": len(alerts)
            }
        )

@app.post("/api/auth/register")
async def register(req: RegisterRequest, request: Request):
    ip_addr = get_client_ip(request)
    cid = req.company_id or 1
    conn = get_db_connection()
    cursor = conn.cursor()
    
    pass_hash = hashlib.sha256(req.password.encode()).hexdigest()
    try:
        cursor.execute(
            "INSERT INTO users (company_id, username, email, password_hash, role) VALUES (?, ?, ?, ?, 'user')",
            (cid, req.username, req.email, pass_hash)
        )
        conn.commit()
        conn.close()
        
        log_activity(
            company_id=cid,
            action="USER_REGISTERED",
            ip_address=ip_addr,
            status="SUCCESS",
            username=req.username,
            details=f"New user registered: {req.username}"
        )
        return {"status": "success", "message": "User registered successfully"}
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Username or Email already exists")

# --- SOC DASHBOARD API ENDPOINTS (MULTI-TENANT SCOPED) ---

@app.get("/api/admin/metrics")
async def get_metrics(company_id: int = Query(1)):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as cnt FROM users WHERE company_id = ?", (company_id,))
    total_users = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM activity_logs WHERE company_id = ?", (company_id,))
    total_logs = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM activity_logs WHERE company_id = ? AND status = 'SUCCESS'", (company_id,))
    normal_logs = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM activity_logs WHERE company_id = ? AND status != 'SUCCESS'", (company_id,))
    suspicious_logs = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM security_alerts WHERE company_id = ? AND status = 'ACTIVE'", (company_id,))
    active_alerts = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM security_alerts WHERE company_id = ? AND severity = 'CRITICAL' AND status = 'ACTIVE'", (company_id,))
    critical_alerts = cursor.fetchone()['cnt']

    cursor.execute("SELECT severity, COUNT(*) as cnt FROM security_alerts WHERE company_id = ? GROUP BY severity", (company_id,))
    sev_counts = {row['severity']: row['cnt'] for row in cursor.fetchall()}

    conn.close()

    # Get active subscription plan
    sub = get_company_subscription(company_id)

    return {
        "company_id": company_id,
        "plan_name": sub.get("plan_name", "FREE"),
        "total_users": total_users,
        "total_logs": total_logs,
        "normal_logs": normal_logs,
        "suspicious_logs": suspicious_logs,
        "active_alerts": active_alerts,
        "critical_alerts": critical_alerts,
        "severity_distribution": {
            "CRITICAL": sev_counts.get("CRITICAL", 0),
            "HIGH": sev_counts.get("HIGH", 0),
            "MEDIUM": sev_counts.get("MEDIUM", 0),
            "LOW": sev_counts.get("LOW", 0)
        }
    }

@app.get("/api/admin/alerts")
async def get_alerts(company_id: int = Query(1), status_filter: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if status_filter:
        cursor.execute("SELECT * FROM security_alerts WHERE company_id = ? AND status = ? ORDER BY id DESC LIMIT 50", (company_id, status_filter))
    else:
        cursor.execute("SELECT * FROM security_alerts WHERE company_id = ? ORDER BY id DESC LIMIT 50", (company_id,))
    alerts = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"alerts": alerts}

@app.get("/api/admin/logs")
async def get_logs(company_id: int = Query(1), search: Optional[str] = None, limit: int = 50):
    conn = get_db_connection()
    cursor = conn.cursor()
    if search:
        query = "%" + search + "%"
        cursor.execute("""
            SELECT * FROM activity_logs 
            WHERE company_id = ? AND (username LIKE ? OR action LIKE ? OR ip_address LIKE ? OR status LIKE ?)
            ORDER BY id DESC LIMIT ?
        """, (company_id, query, query, query, query, limit))
    else:
        cursor.execute("SELECT * FROM activity_logs WHERE company_id = ? ORDER BY id DESC LIMIT ?", (company_id, limit))
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"logs": logs}

@app.post("/api/admin/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE security_alerts SET status = 'RESOLVED' WHERE id = ?", (alert_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"Alert #{alert_id} resolved by Security Administrator"}

@app.get("/api/admin/export/logs")
async def export_logs_csv(company_id: int = Query(1)):
    """Exports tenant audit logs to a downloadable CSV file for SOC compliance."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, action, username, ip_address, status, details, user_agent 
        FROM activity_logs 
        WHERE company_id = ? 
        ORDER BY id DESC LIMIT 500
    """, (company_id,))
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Action", "Username", "Source IP", "Status", "Details", "User Agent"])
    for r in rows:
        writer.writerow([r["timestamp"], r["action"], r["username"], r["ip_address"], r["status"], r["details"], r["user_agent"]])
    
    output.seek(0)
    filename = f"cloudshield_tenant_{company_id}_audit_logs.csv"
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.get("/api/admin/export/alerts")
async def export_alerts_json(company_id: int = Query(1)):
    """Exports active and mitigated security incidents in standard JSON format."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, alert_type, severity, target_user, source_ip, message, status, mitigation_action
        FROM security_alerts 
        WHERE company_id = ? 
        ORDER BY id DESC
    """, (company_id,))
    alerts = [dict(row) for row in cursor.fetchall()]
    conn.close()

    comp = get_company(company_id)
    company_name = comp["name"] if comp else f"Tenant_{company_id}"

    return {
        "export_metadata": {
            "platform": "CloudShield SIEM",
            "company_id": company_id,
            "company_name": company_name,
            "total_incidents": len(alerts),
            "compliance_standard": "ISO/IEC 27001 Log Compliance"
        },
        "incidents": alerts
    }

# --- REAL-TIME LIVE INGESTION GATEWAY ---

@app.get("/api/v1/ping")
async def ping_gateway():
    """Health check for external security agents & ingestion clients."""
    return {
        "status": "online",
        "service": "CloudShield Real-Time Ingestion Gateway",
        "version": "2.0.0",
        "ingest_endpoint": "/api/v1/events",
        "supported_auth": ["X-API-Key Header", "JSON body 'api_key'", "Authorization: Bearer <key>"]
    }

@app.post("/api/v1/events")
async def ingest_security_event(req: EventIngestRequest, request: Request):
    """
    Live real-time security audit ingestion endpoint.
    Servers, microservices, cloud VMs, and client agents stream real-time logs here.
    Authenticates via tenant API key in request body, 'X-API-Key' header, or 'Authorization: Bearer <key>'.
    """
    api_key = req.api_key
    if not api_key:
        api_key = request.headers.get("X-API-Key")
    if not api_key:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            api_key = auth_header.split(" ", 1)[1].strip()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide 'api_key' in JSON payload or 'X-API-Key' header."
        )

    company = get_company_by_api_key(api_key)
    if not company:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key. Organization not recognized on CloudShield."
        )

    company_id = company["id"]
    ip_addr = req.ip_address if req.ip_address else get_client_ip(request)
    user_agent = req.user_agent or request.headers.get("User-Agent", "CloudShield-Agent/1.0")

    # Ingest log into database
    log_id = log_activity(
        company_id=company_id,
        action=req.action.strip().upper(),
        ip_address=ip_addr.strip(),
        status=req.status.strip().upper(),
        username=(req.username or "anonymous").strip(),
        user_agent=user_agent,
        details=req.details or f"Live security event received from {ip_addr}"
    )

    # Immediately trigger real-time multi-tenant threat detection rules
    alerts = evaluate_security_rules(
        company_id=company_id,
        latest_ip=ip_addr.strip(),
        latest_username=(req.username or "anonymous").strip()
    )

    return {
        "status": "success",
        "message": "Real-time security event ingested & evaluated",
        "event_id": log_id,
        "company_id": company_id,
        "company_name": company["name"],
        "alerts_triggered": len(alerts),
        "details": {
            "action": req.action.strip().upper(),
            "ip_address": ip_addr.strip(),
            "username": (req.username or "anonymous").strip(),
            "status": req.status.strip().upper()
        }
    }

# --- STATIC FILES & ROOT ---

static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir)

app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def read_root():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "CloudShield Platform API is running. Create static/index.html"}
