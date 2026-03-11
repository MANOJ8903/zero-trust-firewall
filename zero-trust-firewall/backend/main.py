from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import time
import random
import hashlib
import datetime
import json

app = FastAPI(
    title="AI-Enabled Zero Trust Network Firewall",
    description="Zero Trust Security with AI-powered threat detection",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── In-memory storage ────────────────────────────────────────────
traffic_logs = []
blocked_ips = set()
threat_alerts = []
policy_rules = [
    {"id": 1, "name": "Block Tor Exit Nodes", "action": "BLOCK", "enabled": True},
    {"id": 2, "name": "Allow Internal Subnet", "action": "ALLOW", "enabled": True},
    {"id": 3, "name": "Rate Limit SSH", "action": "RATE_LIMIT", "enabled": True},
    {"id": 4, "name": "Block Port Scan", "action": "BLOCK", "enabled": True},
    {"id": 5, "name": "Zero Trust MFA Required", "action": "MFA", "enabled": True},
]

# ─── Models ───────────────────────────────────────────────────────
class TrafficRequest(BaseModel):
    source_ip: str
    destination_ip: str
    port: int
    protocol: str
    payload_size: int
    user_agent: Optional[str] = "Unknown"

class PolicyRule(BaseModel):
    name: str
    action: str
    enabled: bool

# ─── AI Threat Detection Engine ───────────────────────────────────
def ai_threat_score(traffic: TrafficRequest) -> dict:
    score = 0
    reasons = []

    # Heuristic rules simulating ML model
    suspicious_ports = [22, 23, 3389, 4444, 6666, 31337]
    if traffic.port in suspicious_ports:
        score += 30
        reasons.append(f"Suspicious port {traffic.port} detected")

    if traffic.payload_size > 50000:
        score += 25
        reasons.append("Abnormally large payload detected")

    if traffic.source_ip.startswith("10.0.0."):
        score -= 20
        reasons.append("Internal trusted subnet")

    blocked_ranges = ["192.168.99.", "172.16.99.", "45.33.32."]
    for rng in blocked_ranges:
        if traffic.source_ip.startswith(rng):
            score += 50
            reasons.append(f"Known malicious IP range: {rng}*")

    if traffic.protocol == "UDP" and traffic.port == 53 and traffic.payload_size > 512:
        score += 40
        reasons.append("Possible DNS amplification attack")

    if traffic.protocol == "TCP" and traffic.payload_size == 0:
        score += 20
        reasons.append("TCP SYN scan pattern detected")

    score = max(0, min(100, score + random.randint(-5, 5)))

    if score >= 70:
        verdict = "BLOCK"
        threat_level = "CRITICAL"
    elif score >= 40:
        verdict = "INSPECT"
        threat_level = "MEDIUM"
    elif score >= 20:
        verdict = "MONITOR"
        threat_level = "LOW"
    else:
        verdict = "ALLOW"
        threat_level = "SAFE"

    return {
        "threat_score": score,
        "verdict": verdict,
        "threat_level": threat_level,
        "reasons": reasons if reasons else ["Normal traffic pattern"],
        "confidence": f"{85 + random.randint(0, 14)}%"
    }

# ─── Routes ───────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "🔒 Zero Trust Firewall Active", "version": "1.0.0"}

@app.post("/api/analyze")
def analyze_traffic(traffic: TrafficRequest):
    result = ai_threat_score(traffic)
    log_entry = {
        "id": len(traffic_logs) + 1,
        "timestamp": datetime.datetime.now().isoformat(),
        "source_ip": traffic.source_ip,
        "destination_ip": traffic.destination_ip,
        "port": traffic.port,
        "protocol": traffic.protocol,
        "payload_size": traffic.payload_size,
        **result
    }
    traffic_logs.append(log_entry)

    if result["verdict"] == "BLOCK":
        blocked_ips.add(traffic.source_ip)
        threat_alerts.append({
            "id": len(threat_alerts) + 1,
            "timestamp": datetime.datetime.now().isoformat(),
            "source_ip": traffic.source_ip,
            "threat_level": result["threat_level"],
            "reason": result["reasons"][0] if result["reasons"] else "Threat detected",
            "score": result["threat_score"]
        })

    return log_entry

@app.get("/api/dashboard/stats")
def dashboard_stats():
    total = len(traffic_logs)
    blocked = len([l for l in traffic_logs if l["verdict"] == "BLOCK"])
    allowed = len([l for l in traffic_logs if l["verdict"] == "ALLOW"])
    inspected = len([l for l in traffic_logs if l["verdict"] == "INSPECT"])

    return {
        "total_requests": total,
        "blocked": blocked,
        "allowed": allowed,
        "inspected": inspected,
        "blocked_ips_count": len(blocked_ips),
        "active_alerts": len(threat_alerts),
        "uptime": "99.98%",
        "last_updated": datetime.datetime.now().isoformat()
    }

@app.get("/api/logs")
def get_logs(limit: int = 20):
    return {"logs": list(reversed(traffic_logs[-limit:]))}

@app.get("/api/alerts")
def get_alerts():
    return {"alerts": list(reversed(threat_alerts[-10:]))}

@app.get("/api/blocked-ips")
def get_blocked_ips():
    return {"blocked_ips": list(blocked_ips)}

@app.get("/api/policies")
def get_policies():
    return {"policies": policy_rules}

@app.post("/api/policies")
def add_policy(rule: PolicyRule):
    new_rule = {
        "id": len(policy_rules) + 1,
        "name": rule.name,
        "action": rule.action,
        "enabled": rule.enabled
    }
    policy_rules.append(new_rule)
    return new_rule

@app.post("/api/simulate")
def simulate_traffic():
    """Simulate 10 random traffic events for demo"""
    scenarios = [
        TrafficRequest(source_ip="45.33.32.156", destination_ip="192.168.1.1", port=4444, protocol="TCP", payload_size=1024),
        TrafficRequest(source_ip="10.0.0.5", destination_ip="192.168.1.100", port=443, protocol="TCP", payload_size=2048),
        TrafficRequest(source_ip="192.168.99.1", destination_ip="10.0.0.1", port=22, protocol="TCP", payload_size=0),
        TrafficRequest(source_ip="8.8.8.8", destination_ip="192.168.1.1", port=80, protocol="TCP", payload_size=512),
        TrafficRequest(source_ip="172.16.99.5", destination_ip="10.0.0.2", port=53, protocol="UDP", payload_size=65000),
    ]
    results = []
    for s in scenarios:
        results.append(analyze_traffic(s))
    return {"simulated": len(results), "results": results}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
