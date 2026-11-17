import sqlite3
import os
import json
from datetime import datetime, timedelta
import hashlib

DB_PATH = os.path.join(os.path.dirname(__file__), "cloud_security.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Companies Table (Multi-Tenancy)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            domain TEXT,
            api_key TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 2. Plans Table (Freemium SaaS Tiers)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            price INTEGER NOT NULL,
            billing_cycle TEXT DEFAULT 'month',
            description TEXT,
            features TEXT
        )
    ''')

    # 3. Subscriptions Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL,
            plan_id INTEGER NOT NULL,
            status TEXT DEFAULT 'ACTIVE',
            start_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            end_date DATETIME,
            FOREIGN KEY (company_id) REFERENCES companies(id),
            FOREIGN KEY (plan_id) REFERENCES plans(id)
        )
    ''')

    # 4. Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER DEFAULT 1,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (company_id) REFERENCES companies(id)
        )
    ''')
    
    # 5. Activity Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER DEFAULT 1,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            action TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            status TEXT NOT NULL,
            details TEXT,
            FOREIGN KEY (company_id) REFERENCES companies(id)
        )
    ''')
    
    # 6. Security Alerts Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER DEFAULT 1,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            target_user TEXT,
            source_ip TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT DEFAULT 'ACTIVE',
            mitigation_action TEXT,
            FOREIGN KEY (company_id) REFERENCES companies(id)
        )
    ''')

    # Migration check: Ensure company_id exists in case tables were previously created without it
    for table in ['activity_logs', 'security_alerts', 'users']:
        cursor.execute(f"PRAGMA table_info({table})")
        cols = [row['name'] for row in cursor.fetchall()]
        if 'company_id' not in cols:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN company_id INTEGER DEFAULT 1")

    # Seed Plans if empty
    cursor.execute("SELECT COUNT(*) as cnt FROM plans")
    if cursor.fetchone()['cnt'] == 0:
        plans_data = [
            (
                "FREE", 0, "month",
                "Essential security monitoring for small applications and startups.",
                json.dumps(["audit_logs", "rule_detection", "basic_dashboard", "standard_alerts"])
            ),
            (
                "PROFESSIONAL", 999, "month",
                "AI-driven anomaly detection, advanced incident forensics & real-time response.",
                json.dumps(["audit_logs", "rule_detection", "basic_dashboard", "standard_alerts", "ml_anomalies", "advanced_analytics", "email_alerts", "extended_retention"])
            ),
            (
                "ENTERPRISE", 4999, "month",
                "Dedicated SOC infrastructure, custom threat rules & 24/7 priority response.",
                json.dumps(["audit_logs", "rule_detection", "basic_dashboard", "standard_alerts", "ml_anomalies", "advanced_analytics", "email_alerts", "extended_retention", "custom_rules", "priority_soc"])
            )
        ]
        cursor.executemany(
            "INSERT INTO plans (name, price, billing_cycle, description, features) VALUES (?, ?, ?, ?, ?)",
            plans_data
        )

    # Seed Default Tenant Companies if empty
    cursor.execute("SELECT COUNT(*) as cnt FROM companies")
    if cursor.fetchone()['cnt'] == 0:
        cursor.execute(
            "INSERT INTO companies (name, domain, api_key) VALUES (?, ?, ?)",
            ("Acme Cloud Systems", "acme-cloud.io", "acme_sec_live_9921")
        )
        cursor.execute(
            "INSERT INTO companies (name, domain, api_key) VALUES (?, ?, ?)",
            ("Nexus Cyber Tech", "nexus-cyber.com", "nexus_sec_live_4410")
        )
        # Assign Company 1 -> FREE, Company 2 -> PROFESSIONAL
        # plan_id 1 is FREE, plan_id 2 is PROFESSIONAL
        cursor.execute("SELECT id FROM plans WHERE name = 'FREE'")
        free_id = cursor.fetchone()['id']
        cursor.execute("SELECT id FROM plans WHERE name = 'PROFESSIONAL'")
        pro_id = cursor.fetchone()['id']

        end_date = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO subscriptions (company_id, plan_id, status, end_date) VALUES (1, ?, 'ACTIVE', ?)",
            (free_id, end_date)
        )
        cursor.execute(
            "INSERT INTO subscriptions (company_id, plan_id, status, end_date) VALUES (2, ?, 'ACTIVE', ?)",
            (pro_id, end_date)
        )

    # Seed default admin & student user if not exists
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        admin_pass_hash = hashlib.sha256("Admin@123".encode()).hexdigest()
        cursor.execute(
            "INSERT INTO users (company_id, username, email, password_hash, role) VALUES (?, ?, ?, ?, ?)",
            (1, "admin", "admin@cloudsec.local", admin_pass_hash, "admin")
        )
        user_pass_hash = hashlib.sha256("User@123".encode()).hexdigest()
        cursor.execute(
            "INSERT INTO users (company_id, username, email, password_hash, role) VALUES (?, ?, ?, ?, ?)",
            (1, "student_user", "student@cloudsec.local", user_pass_hash, "user")
        )

    conn.commit()
    conn.close()
    print("Database multi-tenant schema initialized successfully.")

# --- Multi-Tenant & Subscription Helper Functions ---

def get_company(company_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM companies WHERE id = ?", (company_id,))
    comp = cursor.fetchone()
    conn.close()
    return dict(comp) if comp else None

def get_company_by_api_key(api_key: str):
    if not api_key:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM companies WHERE api_key = ?", (api_key.strip(),))
    comp = cursor.fetchone()
    conn.close()
    return dict(comp) if comp else None

def get_all_companies():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT c.*, p.name as plan_name, p.price as plan_price, s.status as subscription_status
        FROM companies c
        LEFT JOIN subscriptions s ON c.id = s.company_id AND s.status = 'ACTIVE'
        LEFT JOIN plans p ON s.plan_id = p.id
        ORDER BY c.id ASC
    ''')
    companies = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return companies

def get_company_subscription(company_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT s.*, p.name as plan_name, p.price, p.features, p.description
        FROM subscriptions s
        JOIN plans p ON s.plan_id = p.id
        WHERE s.company_id = ? AND s.status = 'ACTIVE'
        ORDER BY s.id DESC LIMIT 1
    ''', (company_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        sub = dict(row)
        try:
            sub['features'] = json.loads(sub['features'])
        except Exception:
            sub['features'] = []
        return sub
    return {
        "plan_name": "FREE",
        "price": 0,
        "features": ["audit_logs", "rule_detection", "basic_dashboard", "standard_alerts"],
        "status": "ACTIVE"
    }

def get_plans():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM plans ORDER BY price ASC")
    plans = []
    for row in cursor.fetchall():
        p = dict(row)
        try:
            p['features'] = json.loads(p['features'])
        except Exception:
            p['features'] = []
        plans.append(p)
    conn.close()
    return plans

def upgrade_subscription(company_id: int, plan_name: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM plans WHERE name = ?", (plan_name.upper(),))
    plan = cursor.fetchone()
    if not plan:
        conn.close()
        return False, "Plan not found"
    
    plan_id = plan['id']
    end_date = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")

    # Deactivate existing active subscriptions
    cursor.execute("UPDATE subscriptions SET status = 'SUPERSEDED' WHERE company_id = ? AND status = 'ACTIVE'", (company_id,))

    # Insert new active subscription
    cursor.execute(
        "INSERT INTO subscriptions (company_id, plan_id, status, end_date) VALUES (?, ?, 'ACTIVE', ?)",
        (company_id, plan_id, end_date)
    )
    conn.commit()
    conn.close()
    return True, f"Successfully upgraded company #{company_id} to {plan_name.upper()} plan"

# Helper functions for logs and alerts
def log_activity(action: str, ip_address: str, status: str, username: str = "anonymous", user_agent: str = "WebBrowser", details: str = "", company_id: int = 1):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO activity_logs (company_id, username, action, ip_address, user_agent, status, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (company_id, username, action, ip_address, user_agent, status, details))
    log_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return log_id

def create_security_alert(alert_type: str, severity: str, source_ip: str, message: str, target_user: str = None, mitigation_action: str = "IP Blocked & Session Revoked", company_id: int = 1):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Avoid duplicate active alerts for same type and IP within short window for this company
    cursor.execute('''
        SELECT id FROM security_alerts 
        WHERE company_id = ? AND alert_type = ? AND source_ip = ? AND status = 'ACTIVE'
    ''', (company_id, alert_type, source_ip))
    existing = cursor.fetchone()
    
    if not existing:
        cursor.execute('''
            INSERT INTO security_alerts (company_id, alert_type, severity, target_user, source_ip, message, status, mitigation_action)
            VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
        ''', (company_id, alert_type, severity, target_user, source_ip, message, mitigation_action))
        alert_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return alert_id
    
    conn.close()
    return existing['id']

if __name__ == "__main__":
    init_db()


def register_new_company(company_name: str, domain: str, admin_username: str, admin_email: str, password_hash: str):
    """
    Registers a brand new tenant organization into the cloud platform.
    Automatically assigns them the FREE plan and provisions an admin user.
    """
    import random
    conn = get_db_connection()
    cursor = conn.cursor()

    # Generate a unique API key for the tenant
    clean_name = company_name.lower().replace(" ", "_")[:8]
    rand_code = random.randint(1000, 9999)
    api_key = f"{clean_name}_live_sec_{rand_code}"

    try:
        # 1. Insert Company
        cursor.execute(
            "INSERT INTO companies (name, domain, api_key) VALUES (?, ?, ?)",
            (company_name, domain or f"{clean_name}.io", api_key)
        )
        company_id = cursor.lastrowid

        # 2. Assign Default FREE Subscription
        cursor.execute("SELECT id FROM plans WHERE name = 'FREE'")
        free_plan = cursor.fetchone()
        plan_id = free_plan['id'] if free_plan else 1
        end_date = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute(
            "INSERT INTO subscriptions (company_id, plan_id, status, end_date) VALUES (?, ?, 'ACTIVE', ?)",
            (company_id, plan_id, end_date)
        )

        # 3. Create Company Admin User
        cursor.execute(
            "INSERT INTO users (company_id, username, email, password_hash, role) VALUES (?, ?, ?, ?, 'admin')",
            (company_id, admin_username, admin_email, password_hash)
        )

        # 4. Log the initial provisioning audit event
        cursor.execute('''
            INSERT INTO activity_logs (company_id, username, action, ip_address, user_agent, status, details)
            VALUES (?, ?, 'TENANT_ONBOARDED', '127.0.0.1', 'CloudShield-Provisioner', 'SUCCESS', ?)
        ''', (company_id, admin_username, f"Organization '{company_name}' onboarded to CloudShield with FREE Tier"))

        conn.commit()
        conn.close()
        return True, {
            "company_id": company_id,
            "company_name": company_name,
            "api_key": api_key,
            "plan": "FREE"
        }

    except sqlite3.IntegrityError as e:
        conn.close()
        return False, "An organization with that name or an account with that email/username already exists."
    except Exception as e:
        conn.close()
        return False, str(e)
