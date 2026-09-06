import json
import random

from llm.client import generate_json


SAFE_SCENARIOS = [
    {
        "attack_type": "XSS",
        "scenario": "search_xss_simulation",
        "target": "/search",
        "severity": "HIGH"
    },
    {
        "attack_type": "SQL Injection",
        "scenario": "login_sqli_simulation",
        "target": "/login",
        "severity": "CRITICAL"
    },
    {
        "attack_type": "Authentication Attack",
        "scenario": "login_auth_simulation",
        "target": "/login",
        "severity": "HIGH"
    }
]


def get_scenario_by_name(
    scenario_name
):
    for scenario in SAFE_SCENARIOS:
        if scenario["scenario"] == scenario_name:
            return scenario.copy()

    return None


def select_attack(
    experience_context=None
):
    """
    Attacker AI.

    LLM이 SAFE_SCENARIOS 중 하나만 선택할 수 있다.
    임의 공격 실행은 허용하지 않는다.
    """

    if experience_context is None:
        experience_context = []

    available_actions = [
        {
            "scenario": item["scenario"],
            "attack_type": item["attack_type"],
            "target": item["target"],
            "severity": item["severity"]
        }
        for item in SAFE_SCENARIOS
    ]

    system_prompt = """
You are the attacker agent in an isolated cybersecurity
simulation environment.

Your task is NOT to generate exploit code.

You may ONLY select one scenario from the provided
SAFE_SCENARIOS.

Use previous simulation experience to select the scenario
that is most likely to succeed against the defender.

Return JSON only.

Required format:

{
  "scenario": "one exact scenario name",
  "reason": "short reason"
}
""".strip()

    user_prompt = f"""
SAFE_SCENARIOS:

{json.dumps(
    available_actions,
    ensure_ascii=False,
    indent=2
)}

PAST ATTACKER EXPERIENCE:

{json.dumps(
    experience_context,
    ensure_ascii=False,
    indent=2,
    default=str
)}

Select exactly one allowed scenario.
""".strip()

    try:

        decision = generate_json(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_new_tokens=64
        )

        scenario_name = decision.get(
            "scenario"
        )

        selected = get_scenario_by_name(
            scenario_name
        )

        # LLM이 허용되지 않은 값을 반환하면 거부
        if selected is None:
            raise ValueError(
                f"LLM selected invalid scenario: "
                f"{scenario_name}"
            )

        selected["model"] = "llm-attacker"
        selected["version"] = "v0.1"

        selected["reason"] = decision.get(
            "reason",
            ""
        )

        selected["experiences"] = (
            experience_context
        )

        return selected

    except Exception as e:

        # 모델 장애 시 Battle 전체가 죽지 않도록
        # 기존 random attacker fallback

        print(
            f"[ATTACKER AI FALLBACK] {e}"
        )

        selected = random.choice(
            SAFE_SCENARIOS
        ).copy()

        selected["model"] = (
            "scenario-attacker-fallback"
        )

        selected["version"] = "v0.1"

        selected["reason"] = (
            "LLM unavailable - random fallback"
        )

        selected["experiences"] = (
            experience_context
        )

        return selected