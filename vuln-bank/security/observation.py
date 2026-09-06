import time
from flask import request, g

IGNORED_PATHS = {
    "/api/health",
    "/api/events"
}

OBSERVED_ENDPOINTS = {
    "/",
    "/login",
    "/register",
    "/search",
    "/transfer",
}


def should_observe():

    if request.path.startswith("/static/"):
        return False

    if request.path.startswith("/api/"):
        return False

    return request.path in OBSERVED_ENDPOINTS

# def should_observe():
#     return request.path not in IGNORED_PATHS

def start_observation():
    """요청 시작 시각 기록"""
    g.request_start_time = time.perf_counter()


def build_observation(response):
    """Defender가 볼 수 있는 HTTP 관측 데이터 생성"""

    start = getattr(g, "request_start_time", None)

    response_time_ms = None
    if start is not None:
        response_time_ms = round(
            (time.perf_counter() - start) * 1000,
            2
        )

    # query string
    query_params = request.args.to_dict(flat=False)

    # form body
    form_params = request.form.to_dict(flat=False)

    # JSON body
    json_body = request.get_json(silent=True)

    observation = {
        "timestamp": time.time(),

        "method": request.method,
        "endpoint": request.path,

        "query_params": sanitize(query_params),
        "form_params": sanitize(form_params),
        "json_body": sanitize(json_body),

        "http_status": response.status_code,
        "response_time_ms": response_time_ms,

        "content_type": request.content_type,

        "user_agent": request.headers.get(
            "User-Agent", ""
        ),

        "content_length": request.content_length
    }

    return observation


def sanitize(data):
    """
    비밀번호 / 토큰 / 세션 등 민감정보 제거
    """

    if not isinstance(data, dict):
        return data

    sensitive_keys = {
        "password",
        "passwd",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "session"
    }

    cleaned = {}

    for key, value in data.items():

        if key.lower() in sensitive_keys:
            cleaned[key] = "[REDACTED]"
        else:
            cleaned[key] = value

    return cleaned
