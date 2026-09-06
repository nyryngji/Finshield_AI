from flask import Blueprint, jsonify, request
from datetime import datetime, timezone
import random

security_api = Blueprint("security_api", __name__)

security_events = []


@security_api.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "service": "VulnBank Cyber Defense"
    })


@security_api.route("/api/security/events", methods=["GET"])
def get_events():
    return jsonify({
        "events": list(reversed(security_events[-100:]))
    })


@security_api.route("/api/attack/simulate", methods=["POST"])
def simulate_attack():

    data = request.get_json(silent=True) or {}

    scenarios = {
        "sql_injection": {
            "name": "SQL Injection",
            "severity": "CRITICAL"
        },
        "xss": {
            "name": "Cross-Site Scripting",
            "severity": "HIGH"
        },
        "auth_attack": {
            "name": "Authentication Attack",
            "severity": "HIGH"
        }
    }

    attack_type = data.get("attack_type")

    if not attack_type:
        attack_type = random.choice(
            list(scenarios.keys())
        )

    scenario = scenarios.get(attack_type)

    if not scenario:
        return jsonify({
            "error": "Unknown attack type"
        }), 400

    event = {
        "id": len(security_events) + 1,
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "attack_type": scenario["name"],
        "severity": scenario["severity"],

        # 지금은 임시
        "detected": True,
        "defense_status": "ANALYZED",
        "confidence": round(
            random.uniform(0.85, 0.99),
            2
        )
    }

    security_events.append(event)

    return jsonify({
        "success": True,
        "event": event
    })