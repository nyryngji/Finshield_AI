from db_work.cyber_db import (
    save_security_observation,
    save_ground_truth,
)


def execute_scenario(attack):
    """
    허용된 시뮬레이션 시나리오를 실행하고
    VulnBank에서 Defender가 볼 Observation을 생성한다.
    """

    scenario = attack["scenario"]

    if scenario == "search_xss_simulation":
        observation = {
            "method": "GET",
            "endpoint": "/search",
            "query_params": {
                "q": ["[XSS_TEST_INPUT]"]
            },
            "form_params": {},
            "json_body": None,
            "http_status": 200,
            "response_time_ms": 10,
            "content_type": "text/html"
        }

        attack_success = True

    elif scenario == "login_sqli_simulation":
        observation = {
            "method": "POST",
            "endpoint": "/login",
            "query_params": {},
            "form_params": {},
            "json_body": {
                "username": "[SQLI_TEST_INPUT]",
                "password": "[REDACTED]"
            },
            "http_status": 401,
            "response_time_ms": 8,
            "content_type": "application/json"
        }

        attack_success = False

    elif scenario == "login_auth_simulation":
        observation = {
            "method": "POST",
            "endpoint": "/login",
            "query_params": {},
            "form_params": {},
            "json_body": {
                "username": "test-user",
                "password": "[REDACTED]"
            },
            "http_status": 401,
            "response_time_ms": 5,
            "content_type": "application/json",

            # 나중에는 실제 최근 이벤트 DB에서 계산
            "recent_login_failures": 8
        }

        attack_success = False

    else:
        raise ValueError(
            f"허용되지 않은 scenario: {scenario}"
        )

    # Observation 저장
    event_id = save_security_observation(
        observation
    )

    # Ground Truth 저장
    ground_truth = {
        "is_attack": True,
        "attack_type": attack["attack_type"],
        "severity": attack["severity"]
    }

    # 기존 함수 signature에 맞게 조정 필요
    save_ground_truth(
        event_id,
        {
            "attack_type": attack["attack_type"],
            "severity": attack["severity"],
            "mitre_id": None,
            "mitre_tactic": None
        }
    )

    return {
        "event_id": event_id,
        "observation": observation,
        "attack_success": attack_success,
        "ground_truth": ground_truth
    }