"""
AI-Enabled Zero Trust Network Firewall
Main Backend Server (Flask REST API)
"""

import json
import random
import threading
import time
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, send_from_directory
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from ai_engine import AIThreatDetector
from policy_engine import ZeroTrustPolicyEngine

app = Flask(__name__, static_folder="../frontend", static_url_path="")

# ── Core Engines ──────────────────────────────────────────────────────────────
ai = AIThreatDetector()
policy = ZeroTrustPolicyEngine()

# ── In-memory log store ───────────────────────────────────────────────────────
MAX_LOGS = 200
traffic_logs = []
logs_lock = threading.Lock()

# ── Sample IP pool ────────────────────────────────────────────────────────────
SAMPLE_IPS = [
    "192.168.1.10", "10.0.0.5", "172.16.0.23", "203.45.67.89",
    "185.220.101.45", "45.33.32.156", "198.51.100.42", "8.8.8.8",
    "1.1.1.1", "91.108.4.0", "10.0.0.99", "104.21.0.1",
]
DEST_IPS = ["10.0.0.1", "192.168.1.1", "172.16.0.1", "10.10.10.1"]
PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH", "FTP"]
PAYLOADS = [
    "GET /index.html HTTP/1.1",
    "POST /login username=admin&password=admin",
    "SELECT * FROM users WHERE id=1 UNION SELECT * FROM admin--",
    "<script>alert('xss')</script>",
    "Normal HTTP traffic",
    "DNS query: google.com",
    "SSH handshake",
    "beacon c2_connect rat_connect",
    "Normal file transfer",
    "exec xp_cmdshell('dir')",
]


def generate_random_packet():
    src_ip = random.choice(SAMPLE_IPS)
    return {
        "src_ip": src_ip,
        "dst_ip": random.choice(DEST_IPS),
        "protocol": random.choice(PROTOCOLS),
        "port": random.choice([80, 443, 22, 21, 8080, 3306, 4444, 1337, 53, 8443]),
        "size": random.randint(64, 1500),
        "rate": random.uniform(1, 1200),
        "payload": random.choice(PAYLOADS),
        "auth_failures": random.randint(0, 10) if random.random() < 0.15 else 0,
        "bytes": random.randint(100, 60000),
        "geo_anomaly": random.random() < 0.1,
        "time_anomaly": random.random() < 0.05,
    }


def auto_generate_traffic():
    """Background thread: simulates live network traffic."""
    while True:
        packet = generate_random_packet()
        ai_result = ai.analyze_packet(packet)
        policy_result = policy.evaluate(packet, ai_result)
        ai_result["policy"] = policy_result

        with logs_lock:
            traffic_logs.insert(0, ai_result)
            if len(traffic_logs) > MAX_LOGS:
                traffic_logs.pop()

        interval = random.uniform(0.3, 1.2)
        time.sleep(interval)


# Start background traffic simulation
bg = threading.Thread(target=auto_generate_traffic, daemon=True)
bg.start()


# ── CORS helper ───────────────────────────────────────────────────────────────
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


# ── API Routes ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")


@app.route("/api/status")
def status():
    with logs_lock:
        recent = traffic_logs[:50]

    blocked = sum(1 for l in recent if l["action"] == "BLOCK")
    allowed = sum(1 for l in recent if l["action"] == "ALLOW")
    alerted = sum(1 for l in recent if l["action"] in ("ALERT", "CHALLENGE"))

    return jsonify({
        "status": "ACTIVE",
        "uptime": "99.97%",
        "mode": "Zero Trust - Enforce",
        "ai_engine": "Online",
        "policies_active": sum(1 for p in policy.get_policies() if p["enabled"]),
        "total_policies": len(policy.get_policies()),
        "stats": ai.get_stats(),
        "recent_summary": {
            "blocked": blocked,
            "allowed": allowed,
            "alerted": alerted,
            "total": len(recent),
        },
        "threat_level": "HIGH" if blocked > 10 else "MEDIUM" if blocked > 3 else "LOW",
    })


@app.route("/api/logs")
def get_logs():
    limit = int(request.args.get("limit", 50))
    with logs_lock:
        logs = traffic_logs[:limit]
    return jsonify({"logs": logs, "total": len(traffic_logs)})


@app.route("/api/analyze", methods=["POST", "OPTIONS"])
def analyze():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    data = request.get_json(force=True) or {}
    packet = {
        "src_ip": data.get("src_ip", "0.0.0.0"),
        "dst_ip": data.get("dst_ip", "10.0.0.1"),
        "protocol": data.get("protocol", "TCP"),
        "port": int(data.get("port", 80)),
        "payload": data.get("payload", ""),
        "size": 500,
        "rate": 10,
        "bytes": 1000,
    }
    result = ai.analyze_packet(packet)
    policy_result = policy.evaluate(packet, result)
    result["policy"] = policy_result
    return jsonify(result)


@app.route("/api/policies")
def get_policies():
    return jsonify({"policies": policy.get_policies()})


@app.route("/api/policies/<policy_id>/toggle", methods=["POST"])
def toggle_policy(policy_id):
    ok = policy.toggle_policy(policy_id)
    return jsonify({"success": ok})


@app.route("/api/threats/summary")
def threat_summary():
    with logs_lock:
        logs = traffic_logs[:100]

    counts = {}
    for log in logs:
        t = log.get("threat_type", "NONE")
        counts[t] = counts.get(t, 0) + 1

    timeline = []
    for i in range(10):
        t = datetime.now() - timedelta(minutes=i * 2)
        timeline.append({
            "time": t.strftime("%H:%M"),
            "threats": random.randint(0, 15),
            "blocked": random.randint(0, 10),
        })

    return jsonify({
        "threat_types": counts,
        "timeline": list(reversed(timeline)),
        "top_sources": [
            {"ip": "185.220.101.45", "count": 23, "country": "RU"},
            {"ip": "45.33.32.156",   "count": 18, "country": "CN"},
            {"ip": "10.0.0.99",      "count": 12, "country": "Unknown"},
        ],
    })


if __name__ == "__main__":
    print("\n" + "="*60)
    print("  AI-Enabled Zero Trust Network Firewall")
    print("  Server starting on http://localhost:5000")
    print("="*60 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
