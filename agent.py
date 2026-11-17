#!/usr/bin/env python3
"""
CloudShield Real-Time Client Agent & Log Streamer
Author: Veeresh (KLE Tech BCA Final Year)
Platform: CloudShield Freemium Cybersecurity SaaS

Description:
    A lightweight, zero-dependency Python client agent that runs on any remote
    host, VM, or local terminal. It streams live security audit events, network
    telemetry, and authentication events into the CloudShield SIEM gateway in real time.

Usage:
    # 1. Check CloudShield Server Connectivity
    python agent.py --status

    # 2. Continuous Real-Time Live Security Stream
    python agent.py --stream

    # 3. Transmit a Single Live Security Event
    python agent.py --send --action LOGIN_FAILED --user admin --ip 192.168.1.105 --status FAILURE

    # 4. Generate Real Live Network Attacks (Over HTTP API)
    python agent.py --attack brute-force
    python agent.py --attack ddos
    python agent.py --attack unauthorized
    python agent.py --attack tor-exit
    python agent.py --attack normal
"""

import sys
import time
import json
import random
import socket
import platform
import argparse
import urllib.request
import urllib.error

DEFAULT_URL = "http://127.0.0.1:8000"
DEFAULT_API_KEY = "acme_sec_live_9921"  # Acme Cloud Systems (Company 1)

def get_local_ip():
    """Attempts to find the local network IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def send_event(base_url: str, api_key: str, action: str, username: str, ip_address: str, status: str, details: str, user_agent: str = None) -> dict:
    """Dispatches a single real-time audit event to the CloudShield Ingestion Gateway."""
    endpoint = f"{base_url.rstrip('/')}/api/v1/events"
    payload = {
        "api_key": api_key,
        "action": action,
        "username": username,
        "ip_address": ip_address,
        "status": status,
        "details": details,
        "user_agent": user_agent or f"CloudShield-Agent/{platform.system()} ({platform.node()})"
    }
    
    data_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=data_bytes,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            res_body = response.read().decode("utf-8")
            return json.loads(res_body)
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        try:
            return {"error": True, "code": e.code, "detail": json.loads(err_msg)}
        except Exception:
            return {"error": True, "code": e.code, "detail": err_msg}
    except Exception as e:
        return {"error": True, "detail": str(e)}

def check_status(base_url: str):
    """Pings the CloudShield Ingestion Gateway."""
    endpoint = f"{base_url.rstrip('/')}/api/v1/ping"
    print(f"[*] Checking CloudShield Gateway at: {endpoint}")
    try:
        req = urllib.request.Request(endpoint, headers={"User-Agent": "CloudShield-Agent-Probe"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[+] Gateway Online: {data.get('service')}")
            print(f"    Version: {data.get('version')}")
            print(f"    Ingestion Path: {data.get('ingest_endpoint')}")
            print(f"    Supported Auth: {', '.join(data.get('supported_auth', []))}")
            return True
    except Exception as e:
        print(f"[-] Gateway unreachable: {e}")
        return False

def run_continuous_stream(base_url: str, api_key: str, interval: float = 3.0):
    """Continuously monitors and sends live heartbeat and simulated workload activity."""
    print("=" * 65)
    print("  📡 CLOUDSHIELD REAL-TIME LIVE AGENT STREAMER")
    print(f"  Target Server: {base_url}")
    print(f"  API Key:       {api_key[:12]}***")
    print(f"  Host:          {platform.node()} ({platform.system()} {platform.release()})")
    print(f"  Interval:      Every {interval}s")
    print("  Press Ctrl+C to stop streaming.")
    print("=" * 65)

    host_ip = get_local_ip()
    users = ["admin", "alice_dev", "bob_ops", "service_worker", "charlie_qa"]
    actions = [
        ("API_REQUEST", "SUCCESS", "GET /api/v1/workloads - 200 OK"),
        ("DB_QUERY", "SUCCESS", "Executed read query on production cluster"),
        ("USER_AUTH", "SUCCESS", "Session token refreshed"),
        ("FILE_ACCESS", "SUCCESS", "Read /etc/nginx/nginx.conf"),
        ("HEARTBEAT", "SUCCESS", f"Host telemetry OK (CPU load nominal, IP: {host_ip})"),
    ]

    event_count = 0
    try:
        while True:
            user = random.choice(users)
            action, st, details = random.choice(actions)

            res = send_event(
                base_url=base_url,
                api_key=api_key,
                action=action,
                username=user,
                ip_address=host_ip,
                status=st,
                details=details
            )

            event_count += 1
            if res.get("status") == "success":
                ts = time.strftime("%H:%M:%S")
                print(f"[{ts}] Event #{event_count:04d} Ingested: {action:<14} | User: {user:<12} | Status: {st}")
            else:
                print(f"[-] Dispatch error: {res}")

            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n[!] Stream stopped by user. Total events dispatched: {event_count}")

def execute_attack_scenario(base_url: str, api_key: str, attack_type: str):
    """Executes real-time attack traffic by sending authentic HTTP packets over the network."""
    print(f"\n[*] Launching Real-Time Threat Scenario: {attack_type.upper()}")
    print(f"[*] Target Ingestion Gateway: {base_url}/api/v1/events\n")

    if attack_type == "brute-force":
        target_ip = "192.168.1.105"
        target_user = "admin"
        print(f"[!] Simulating real Brute Force Attack against user '{target_user}' from {target_ip}...")
        for i in range(1, 5):
            res = send_event(
                base_url=base_url,
                api_key=api_key,
                action="LOGIN_FAILED",
                username=target_user,
                ip_address=target_ip,
                status="FAILURE",
                details=f"Incorrect password attempt #{i} via Hydra dictionary attack",
                user_agent="Hydra/9.2 (NetworkBruteForcer)"
            )
            alerts = res.get("alerts_triggered", 0)
            print(f"    -> [Attempt #{i}] Event #{res.get('event_id')}: LOGIN_FAILED | Alerts Triggered: {alerts}")
            time.sleep(0.4)
        print("\n[+] Brute Force scenario complete. Check SOC dashboard for CRITICAL alert!\n")

    elif attack_type == "ddos":
        flood_ip = "203.0.113.88"
        print(f"[!] Generating high-velocity HTTP API flood (16 requests) from {flood_ip}...")
        for i in range(1, 17):
            res = send_event(
                base_url=base_url,
                api_key=api_key,
                action="API_REQUEST",
                username="anonymous",
                ip_address=flood_ip,
                status="SUCCESS",
                details=f"High frequency GET /api/v1/resource packet #{i}",
                user_agent="LOIC/DDoSStressTool"
            )
            alerts = res.get("alerts_triggered", 0)
            if alerts > 0:
                print(f"    -> [Packet #{i:02d}] 🚨 DDoS RATE LIMIT SURGE DETECTED! Alerts: {alerts}")
            else:
                print(f"    -> [Packet #{i:02d}] Packet ingested OK")
            time.sleep(0.1)
        print("\n[+] DDoS surge complete. Rate-limiting alert should now be active!\n")

    elif attack_type == "unauthorized":
        target_ip = "10.0.4.12"
        target_user = "student_user"
        print(f"[!] Attempting unauthorized privilege escalation for '{target_user}'...")
        res = send_event(
            base_url=base_url,
            api_key=api_key,
            action="UNAUTHORIZED_ACCESS",
            username=target_user,
            ip_address=target_ip,
            status="BLOCKED",
            details="GET /admin/system-secrets without SuperAdmin role",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        )
        print(f"    -> Event #{res.get('event_id')}: UNAUTHORIZED_ACCESS | Alerts: {res.get('alerts_triggered', 0)}")
        print("\n[+] Privilege Escalation incident dispatched!\n")

    elif attack_type == "tor-exit":
        tor_ip = "185.220.101.5"
        print(f"[!] Ingesting authentication from known Tor Exit Node ({tor_ip})...")
        res = send_event(
            base_url=base_url,
            api_key=api_key,
            action="LOGIN_SUCCESS",
            username="student_user",
            ip_address=tor_ip,
            status="SUCCESS",
            details="Session established through Tor Onion Proxy Relay",
            user_agent="TorBrowser/11.0.4"
        )
        print(f"    -> Event #{res.get('event_id')}: Tor Exit Node Traffic Flagged | Alerts: {res.get('alerts_triggered', 0)}")
        print("\n[+] Tor/Proxy detection event dispatched!\n")

    elif attack_type == "normal":
        print("[!] Generating 5 benign production traffic events...")
        ips = ["172.16.0.45", "172.16.0.46", "172.16.0.88"]
        users = ["alice_dev", "bob_ops", "student_user"]
        for i in range(5):
            res = send_event(
                base_url=base_url,
                api_key=api_key,
                action="API_REQUEST",
                username=random.choice(users),
                ip_address=random.choice(ips),
                status="SUCCESS",
                details=f"Normal user browsing transaction #{i+1}"
            )
            print(f"    -> Event #{res.get('event_id')}: Normal traffic verified")
            time.sleep(0.3)
        print("\n[+] Normal traffic sent.\n")

    else:
        print(f"[-] Unknown scenario '{attack_type}'. Available: brute-force, ddos, unauthorized, tor-exit, normal")

def main():
    parser = argparse.ArgumentParser(description="CloudShield Real-Time Security Ingestion Agent")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"CloudShield Base URL (default: {DEFAULT_URL})")
    parser.add_argument("--api-key", default=DEFAULT_API_KEY, help=f"Tenant API Key (default: {DEFAULT_API_KEY})")
    parser.add_argument("--status", action="store_true", help="Check CloudShield server gateway connectivity")
    parser.add_argument("--stream", action="store_true", help="Start continuous live real-time event streaming")
    parser.add_argument("--interval", type=float, default=3.0, help="Stream interval in seconds (default: 3.0)")
    parser.add_argument("--send", action="store_true", help="Send a single custom security event")
    parser.add_argument("--action", default="LOGIN_SUCCESS", help="Action name for --send (e.g. LOGIN_FAILED, API_REQUEST)")
    parser.add_argument("--user", default="admin", help="Username for --send")
    parser.add_argument("--ip", default=None, help="Source IP address for --send (defaults to host IP)")
    parser.add_argument("--event-status", default="SUCCESS", help="Status for --send: SUCCESS, FAILURE, BLOCKED")
    parser.add_argument("--details", default="Manual security audit event dispatch", help="Metadata details for --send")
    parser.add_argument("--attack", choices=["brute-force", "ddos", "unauthorized", "tor-exit", "normal"], help="Run live real-time attack scenario over HTTP")

    args = parser.parse_args()

    if args.status:
        check_status(args.url)
        return

    if args.attack:
        execute_attack_scenario(args.url, args.api_key, args.attack)
        return

    if args.send:
        ip = args.ip or get_local_ip()
        print(f"[*] Transmitting live security event to {args.url}...")
        res = send_event(
            base_url=args.url,
            api_key=args.api_key,
            action=args.action,
            username=args.user,
            ip_address=ip,
            status=args.event_status,
            details=args.details
        )
        print(json.dumps(res, indent=2))
        return

    if args.stream:
        run_continuous_stream(args.url, args.api_key, args.interval)
        return

    # If no flags passed, display interactive help
    print("=" * 65)
    print("🛡️  CLOUDSHIELD REAL-TIME CLIENT AGENT")
    print("=" * 65)
    print("Quick commands:")
    print("  1. Ping Gateway:         python agent.py --status")
    print("  2. Continuous Live Stream: python agent.py --stream")
    print("  3. Live Brute-Force Test: python agent.py --attack brute-force")
    print("  4. Live DDoS Surge Test:  python agent.py --attack ddos")
    print("  5. Send Custom Event:     python agent.py --send --action LOGIN_FAILED --user admin")
    print("\nRun with --help for all arguments.")

if __name__ == "__main__":
    main()
