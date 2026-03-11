"""
Zero Trust Firewall Policy Engine
Implements: Never Trust, Always Verify
"""

import json
import time
from datetime import datetime


class ZeroTrustPolicyEngine:

    DEFAULT_POLICIES = [
        {"id": "P001", "name": "Block All Inbound by Default",    "type": "DENY",  "priority": 1,  "enabled": True},
        {"id": "P002", "name": "Allow HTTPS (443)",               "type": "ALLOW", "priority": 2,  "enabled": True},
        {"id": "P003", "name": "Allow HTTP (80)",                 "type": "ALLOW", "priority": 3,  "enabled": True},
        {"id": "P004", "name": "Block Known Malicious IPs",       "type": "DENY",  "priority": 4,  "enabled": True},
        {"id": "P005", "name": "Block Tor Exit Nodes",            "type": "DENY",  "priority": 5,  "enabled": True},
        {"id": "P006", "name": "Rate Limit: >1000 req/min",       "type": "LIMIT", "priority": 6,  "enabled": True},
        {"id": "P007", "name": "Require MFA for Admin Ports",     "type": "MFA",   "priority": 7,  "enabled": True},
        {"id": "P008", "name": "Allow DNS (53)",                  "type": "ALLOW", "priority": 8,  "enabled": True},
        {"id": "P009", "name": "Block Non-Standard Ports",        "type": "DENY",  "priority": 9,  "enabled": False},
        {"id": "P010", "name": "GeoBlock High-Risk Countries",    "type": "GEO",   "priority": 10, "enabled": True},
        {"id": "P011", "name": "Deep Packet Inspection: SQL",     "type": "DPI",   "priority": 11, "enabled": True},
        {"id": "P012", "name": "Deep Packet Inspection: XSS",     "type": "DPI",   "priority": 12, "enabled": True},
    ]

    BLOCKED_IPS = [
        "185.220.101.45", "198.96.155.3", "23.129.64.190",
        "10.0.0.99", "172.16.254.1", "203.0.113.666"
    ]

    def __init__(self):
        self.policies = self.DEFAULT_POLICIES.copy()
        self.blocked_ips = set(self.BLOCKED_IPS)
        self.policy_hits = {p["id"]: 0 for p in self.policies}

    def evaluate(self, packet: dict, ai_result: dict) -> dict:
        action = "ALLOW"
        matched_policy = None

        # AI override
        if ai_result["action"] == "BLOCK":
            action = "BLOCK"
            matched_policy = "AI_ENGINE"
        elif packet.get("src_ip") in self.blocked_ips:
            action = "BLOCK"
            matched_policy = "P004"
            self.policy_hits["P004"] += 1
        elif ai_result["risk_level"] == "MEDIUM":
            action = "CHALLENGE"
            matched_policy = "AI_CHALLENGE"
        else:
            matched_policy = "P001"
            self.policy_hits["P001"] += 1

        return {
            "final_action": action,
            "matched_policy": matched_policy,
            "evaluated_at": datetime.now().isoformat(),
            "zero_trust_principle": "Never trust, always verify",
        }

    def get_policies(self):
        return self.policies

    def toggle_policy(self, policy_id: str) -> bool:
        for p in self.policies:
            if p["id"] == policy_id:
                p["enabled"] = not p["enabled"]
                return True
        return False

    def get_policy_stats(self):
        return self.policy_hits
