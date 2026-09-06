from psycopg2.extras import RealDictCursor
from db_work.cyber_db import get_connection


def search_defender_experience(
    observation,
    limit=3
):
    """
    현재 Observation과 관련 있는 과거 Battle 경험 검색.

    v0.1:
    - 같은 endpoint 우선
    - 최근 Battle
    - Defender 평가 결과 포함

    Ground Truth의 실제 공격 유형은 Defender Context에 넣지 않는다.
    """

    endpoint = observation.get("endpoint")
    method = observation.get("method")
    status = observation.get("http_status")

    conn = get_connection()

    try:
        with conn.cursor(
            cursor_factory=RealDictCursor
        ) as cursor:

            cursor.execute(
                '''
                SELECT
                    r.라운드id,

                    b.대상엔드포인트, b."HTTP메서드", b."HTTP상태코드",

                    d.탐지여부, d.예측공격유형, d.예측위험도, d.신뢰도, d.공격분석,

                    e.탐지정확,
                    e.공격유형정확,
                    e.위험도정확,
                    e."MITRE정확",
                    e.대응점수,
                    e.종합점수,

                    r.방어자보상

                FROM 대결라운드 r

                JOIN 공격이벤트 b
                    ON r.공격이벤트id = b.공격id

                JOIN "방어AI분석" d
                    ON b.공격id = d.공격id

                LEFT JOIN "AI평가결과" e
                    ON r.라운드id = e.라운드id

                WHERE
                    b.대상엔드포인트 = %s

                ORDER BY
                    CASE
                        WHEN b."HTTP메서드" = %s
                        THEN 0
                        ELSE 1
                    END,

                    CASE
                        WHEN b."HTTP상태코드" = %s
                        THEN 0
                        ELSE 1
                    END,

                    r.라운드id DESC

                LIMIT %s
                ''',
                (
                    endpoint,
                    method,
                    status,
                    limit
                )
            )

            rows = cursor.fetchall()

    finally:
        conn.close()

    results = []

    for rank, row in enumerate(
        rows,
        start=1
    ):

        score = 1.0

        # endpoint는 WHERE에서 이미 동일
        score += 2.0

        if row["HTTP메서드"] == method:
            score += 1.0

        if row["HTTP상태코드"] == status:
            score += 1.0

        # 과거 평가가 존재하면 유용한 경험으로 가중
        if row["탐지정확"] is not None:
            score += 0.5

        content = {
            "round_id": row["라운드id"],

            "observation": {
                "endpoint": row["대상엔드포인트"],
                "method": row["HTTP메서드"],
                "http_status": row["HTTP상태코드"]
            },

            "defender_prediction": {
                "detected": row["탐지여부"],
                "attack_type": row["예측공격유형"],
                "severity": row["예측위험도"],
                "confidence": (
                    float(row["신뢰도"])
                    if row["신뢰도"] is not None
                    else None
                ),
                "analysis": row["공격분석"]
            },

            "evaluation": {
                "detection_correct": row["탐지정확"],
                "classification_correct": row["공격유형정확"],
                "severity_correct": row["위험도정확"],
                "mitre_correct": row["MITRE정확"],

                "response_score": (
                    float(row["대응점수"])
                    if row["대응점수"] is not None
                    else None
                ),

                "total_score": (
                    float(row["종합점수"])
                    if row["종합점수"] is not None
                    else None
                ),

                "defender_reward": (
                    float(row["방어자보상"])
                    if row["방어자보상"] is not None
                    else None
                )
            }
        }

        results.append({
            "score": score,

            "document_id": (
                f"BATTLE-{row['라운드id']}"
            ),

            "content": content
        })

    # 가장 유사한 경험부터
    results.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    return results

def search_attacker_experience(
    limit=5
):
    """
    Attacker가 과거에 어떤 허용된 시나리오에서
    높은 reward를 받았는지 검색한다.
    """

    conn = get_connection()

    try:
        with conn.cursor(
            cursor_factory=RealDictCursor
        ) as cursor:

            cursor.execute(
                """
                SELECT
                    r.라운드id,
                    a.공격전략,
                    a.선택시나리오,
                    a.목표엔드포인트,
                    a.공격성공여부,
                    a.탐지회피여부,
                    r.승자,
                    r.공격자보상

                FROM 대결라운드 r

                JOIN 공격AI행동 a
                    ON r.라운드id = a.라운드id

                WHERE r.종료시간 IS NOT NULL

                ORDER BY
                    r.공격자보상 DESC,
                    r.라운드id DESC

                LIMIT %s
                """,
                (limit,)
            )

            rows = cursor.fetchall()

    finally:
        conn.close()

    results = []

    for row in rows:

        results.append({
            "round_id": row["라운드id"],
            "attack_type": row["공격전략"],
            "scenario": row["선택시나리오"],
            "target": row["목표엔드포인트"],
            "attack_success": row["공격성공여부"],
            "evasion_success": row["탐지회피여부"],
            "winner": row["승자"],
            "attacker_reward": (
                float(row["공격자보상"])
                if row["공격자보상"] is not None
                else 0.0
            )
        })

    return results