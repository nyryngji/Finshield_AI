import json

from llm.client import generate_json


ALLOWED_ATTACK_TYPES = {
    "NORMAL",
    "XSS",
    "SQL Injection",
    "Authentication Attack"
}


ALLOWED_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
}


ALLOWED_ACTIONS = {
    "ALLOW",
    "MONITOR",
    "BLOCK",
    "REQUIRE_AUTH",
    "RATE_LIMIT"
}

import json

from llm.client import generate_json


def analyze_observation(observation, rag_context=None):

    if rag_context is None:
        rag_context = {
            "system": [],
            "mitre": [],
            "experience": []
        }

    # ==================================================
    # 1. SYSTEM RAG 압축
    # ==================================================

    compact_system = []

    for item in rag_context.get("system", []):
        compact_system.append({
            "title": item.get("title"),
            "content": str(
                item.get("content", "")
            )[:200]
        })

    # ==================================================
    # 2. MITRE RAG 압축
    # ==================================================

    compact_mitre = []

    for item in rag_context.get("mitre", []):
        compact_mitre.append({
            "technique_id": item.get("technique_id"),
            "technique_name": item.get("technique_name"),

            # 길이 제한
            "detection": str(
                item.get("detection", "")
            )[:200]
        })

    # ==================================================
    # 3. Experience RAG 압축
    # ==================================================

    compact_experience = []

    for item in rag_context.get("experience", []):

        content = item.get("content", {})

        observation_data = content.get(
            "observation",
            {}
        )

        prediction = content.get(
            "defender_prediction",
            {}
        )

        evaluation = content.get(
            "evaluation",
            {}
        )

        # 전체 데이터를 넣지 않고
        # 판단에 필요한 정보만 넣음
        compact_experience.append({
            "round_id": content.get("round_id"),

            "method": observation_data.get("method"),
            "endpoint": observation_data.get("endpoint"),
            "http_status": observation_data.get("http_status"),

            "previous_detected": prediction.get("detected"),
            "previous_attack_type": prediction.get("attack_type"),

            "detection_correct": evaluation.get("detection_correct"),
            "classification_correct": evaluation.get(
                "classification_correct"
            ),

            "defender_reward": evaluation.get("defender_reward")
        })

    # ==================================================
    # 4. Defender System Prompt
    # ==================================================

    system_prompt = """
You are Defender AI in an isolated banking cybersecurity simulation.

Analyze the current HTTP observation.

You may use:
- current observation
- system knowledge
- MITRE ATT&CK retrieval
- previous defender experience

Rules:
- Never assume hidden ground truth.
- Only judge observable evidence.
- Previous defender predictions may be wrong.
- If previous evaluation says detection_correct=false,
  that previous decision was incorrect.
- MITRE retrieval may be irrelevant.
- Do not blindly trust MITRE retrieval.
- Keep the response extremely short.

Allowed attack_type:
NORMAL
XSS
SQL Injection
Authentication Attack

Allowed severity:
LOW
MEDIUM
HIGH
CRITICAL

Allowed actions:
ALLOW
MONITOR
BLOCK
REQUIRE_AUTH
RATE_LIMIT

IMPORTANT OUTPUT RULES:
- Return ONLY valid JSON.
- Return exactly ONE JSON object.
- Do NOT use markdown.
- Do NOT use ```json.
- Do NOT add text before or after JSON.
- analysis must be maximum 8 words.
- actions must contain maximum 1 action.

Required format:
{"detected":true,"attack_type":"XSS","severity":"HIGH","confidence":0.9,"mitre_id":null,"analysis":"Suspicious input pattern detected","actions":["BLOCK"]}
""".strip()

    # ==================================================
    # 5. Defender User Prompt
    # ==================================================

    user_prompt = f"""
OBSERVATION:
{json.dumps(
    observation,
    ensure_ascii=False,
    separators=(",", ":"),
    default=str
)}

SYSTEM:
{json.dumps(
    compact_system,
    ensure_ascii=False,
    separators=(",", ":"),
    default=str
)}

MITRE:
{json.dumps(
    compact_mitre,
    ensure_ascii=False,
    separators=(",", ":"),
    default=str
)}

PAST EXPERIENCE:
{json.dumps(
    compact_experience,
    ensure_ascii=False,
    separators=(",", ":"),
    default=str
)}

Classify the observation.
Return one JSON object only.
""".strip()

    # ==================================================
    # 6. LLM 실행
    # ==================================================

    try:

        result = generate_json(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_new_tokens=128
        )

        print(
            "[DEFENDER AI RAW]",
            result
        )

        # ==================================================
        # 7. Validation
        # ==================================================

        validated = validate_defense_result(
            result
        )

        validated["model"] = "llm-defender"
        validated["version"] = "v0.1"

        print(
            f"[DEFENDER AI] "
            f"detected={validated['detected']} "
            f"type={validated['attack_type']} "
            f"severity={validated['severity']} "
            f"confidence={validated['confidence']}"
        )

        return validated

    except Exception as e:

        # ==================================================
        # 8. LLM 실패 시 Rule Defender
        # ==================================================

        print(
            f"[DEFENDER AI FALLBACK] {e}"
        )

        return rule_fallback(
            observation
        )

def validate_defense_result(
    result
):

    detected = bool(
        result.get("detected", False)
    )

    attack_type = result.get(
        "attack_type",
        "NORMAL"
    )

    if attack_type not in ALLOWED_ATTACK_TYPES:
        attack_type = "NORMAL"

    severity = result.get(
        "severity",
        "LOW"
    )

    if severity not in ALLOWED_SEVERITIES:
        severity = "LOW"

    try:
        confidence = float(
            result.get("confidence", 0.5)
        )
    except (TypeError, ValueError):
        confidence = 0.5

    confidence = max(
        0.0,
        min(confidence, 1.0)
    )

    actions = result.get(
        "actions",
        ["MONITOR"]
    )

    if not isinstance(actions, list):
        actions = ["MONITOR"]

    actions = [
        action
        for action in actions
        if action in ALLOWED_ACTIONS
    ]

    if not actions:
        actions = ["MONITOR"]

    # detected=False면 prediction 일관성 유지
    if not detected:
        attack_type = "NORMAL"

    return {
        "model": "llm-defender",
        "version": "v0.1",

        "detected": detected,
        "attack_type": attack_type,
        "severity": severity,
        "confidence": confidence,

        "mitre_id": result.get(
            "mitre_id"
        ),

        "analysis": str(
            result.get(
                "analysis",
                ""
            )
        ),

        "actions": actions
    }


def rule_fallback(
    observation
):

    endpoint = observation.get(
        "endpoint"
    )

    status = observation.get(
        "http_status"
    )

    detected = False
    attack_type = "NORMAL"
    severity = "LOW"
    confidence = 0.70

    analysis = (
        "명확한 공격 징후가 발견되지 않았습니다."
    )

    actions = ["ALLOW"]

    if endpoint == "/login" and status == 401:

        analysis = (
            "로그인 인증 실패가 관측되었습니다. "
            "단일 실패만으로 공격으로 판단하지 않습니다."
        )

        confidence = 0.85

    return {
        "model": "rule-defender-fallback",
        "version": "v0.2",

        "detected": detected,
        "attack_type": attack_type,
        "severity": severity,
        "confidence": confidence,

        "mitre_id": None,

        "analysis": analysis,

        "actions": actions
    }