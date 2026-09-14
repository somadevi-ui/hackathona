"""
Automated Incident Response Engine.

Takes a model prediction (label + confidence) plus event context and
decides an action according to simple playbooks. This simulates what
a SOAR (Security Orchestration, Automation and Response) layer would
do in production -- actions here are LOGGED/SIMULATED, not executed
against real infrastructure.
"""

from datetime import datetime, timezone

# Thresholds tuned for demo purposes
HIGH_CONFIDENCE = 0.85
MEDIUM_CONFIDENCE = 0.55


def decide_action(prediction: int, confidence: float, attack_category: str, src_info: dict):
    """
    prediction: 0 = normal, 1 = attack
    confidence: model's probability estimate for the "attack" class
    attack_category: readable category (dos, probe, r2l, u2r, normal, unknown_attack)
    src_info: dict with contextual fields (e.g. protocol, service) for the log
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    if prediction == 0:
        return {
            "timestamp": timestamp,
            "verdict": "benign",
            "confidence": round(float(confidence), 3),
            "action": "ALLOW",
            "severity": "none",
            "details": src_info,
        }

    # It's flagged as an attack -- decide response tier
    if confidence >= HIGH_CONFIDENCE:
        action = _playbook_for_category(attack_category, tier="auto")
        severity = "high"
    elif confidence >= MEDIUM_CONFIDENCE:
        action = "FLAG_FOR_ANALYST_REVIEW"
        severity = "medium"
    else:
        action = "LOG_ONLY_LOW_CONFIDENCE"
        severity = "low"

    return {
        "timestamp": timestamp,
        "verdict": attack_category,
        "confidence": round(float(confidence), 3),
        "action": action,
        "severity": severity,
        "details": src_info,
    }


def _playbook_for_category(category: str, tier: str):
    """Maps an attack category to a specific simulated containment action."""
    playbooks = {
        "dos": "AUTO_RATE_LIMIT_AND_BLOCK_SOURCE_IP",
        "probe": "AUTO_BLOCK_SOURCE_IP_TEMP_24H",
        "r2l": "AUTO_DISABLE_ACCOUNT_AND_FORCE_MFA_RESET",
        "u2r": "AUTO_ISOLATE_HOST_AND_KILL_PROCESS",
        "unknown_attack": "AUTO_ISOLATE_HOST_PENDING_ANALYST_REVIEW",
    }
    return playbooks.get(category, "AUTO_QUARANTINE_SOURCE")
