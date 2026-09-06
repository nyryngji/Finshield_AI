import os
import psycopg2
from psycopg2.extras import RealDictCursor, Json
from database import *

load_dotenv()

def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "vulnerable_bank"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", "postgres"),
    )

def save_attack_event(attack):
    conn = get_connection()

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                '''
                INSERT INTO 공격이벤트 (
                    요청구분,
                    공격주체,
                    공격유형,
                    공격시나리오,
                    대상엔드포인트,
                    "HTTP메서드",
                    요청파라미터,
                    공격페이로드
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING 공격id
                ''',
                (
                    "ATTACK",
                    attack.get("source", "SIMULATOR"),
                    attack["attack_type"],
                    attack.get("scenario"),
                    attack["target"],
                    attack.get("method", "POST"),
                    Json(attack.get("parameters", {})),
                    attack.get("payload")
                )
            )

            attackid = cursor.fetchone()[0]

        conn.commit()
        return attackid

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

def save_ground_truth(attack_id, attack):
    conn = get_connection()

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                '''
                INSERT INTO 공격정답 (
                    공격id,
                    실제공격여부,
                    실제공격유형,
                    실제위험도,
                    "MITRE기술id",
                    "MITRE전술",
                    공격성공여부,
                    정답검증여부,
                    정답출처
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''',
                (
                    attack_id,
                    True,
                    attack["attack_type"],
                    attack["severity"],
                    attack.get("mitre_id"),
                    attack.get("mitre_tactic"),
                    True,
                    True,
                    "SIMULATION_SCENARIO"
                )
            )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

def save_defense_result(attack_id, defense):
    conn = get_connection()

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                '''
                INSERT INTO "방어AI분석" (
                    공격id,
                    모델이름,
                    모델버전,
                    탐지여부,
                    예측공격유형,
                    예측위험도,
                    신뢰도,
                    "예측MITRE기술id",
                    공격분석,
                    대응방안
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING 분석id
                ''',
                (
                    attack_id,
                    defense.get("model", "rule-defender"),
                    defense.get("version", "v0.1"),
                    defense["detected"],
                    defense["attack_type"],
                    defense["severity"],
                    defense["confidence"],
                    defense.get("mitre_id"),
                    defense["analysis"],
                    Json(defense["actions"])
                )
            )

            analysis_id = cursor.fetchone()[0]

        conn.commit()
        return analysis_id

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

def analyze_attack(event):

    attack_type = event["attack_type"]

    responses = {
        "XSS": {
            "severity": "HIGH",
            "mitre_id": None,
            "analysis": "Cross-Site Scripting 공격 패턴이 탐지되었습니다.",
            "actions": [
                "출력값 인코딩",
                "입력값 검증",
                "Content Security Policy 적용 검토"
            ],
            "confidence": 0.92
        },

        "SQL Injection": {
            "severity": "CRITICAL",
            "mitre_id": None,
            "analysis": "SQL Injection 공격 패턴이 탐지되었습니다.",
            "actions": [
                "Parameterized Query 적용",
                "입력값 검증"
            ],
            "confidence": 0.95
        },

        "Authentication Attack": {
            "severity": "HIGH",
            "mitre_id": None,
            "analysis": "비정상적인 인증 시도가 탐지되었습니다.",
            "actions": [
                "Rate Limit 적용",
                "계정 보호 정책 적용"
            ],
            "confidence": 0.90
        }
    }

    result = responses.get(attack_type)

    return {
        "model": "rule-defender",
        "version": "v0.1",

        "detected": True,

        "attack_type": attack_type,
        "severity": result["severity"],

        "confidence": result["confidence"],

        "mitre_id": result["mitre_id"],

        "analysis": result["analysis"],
        "actions": result["actions"]
    }

def get_attack_events(limit=100):
    conn = get_connection()

    try:
        with conn.cursor(
            cursor_factory=RealDictCursor
        ) as cursor:

            cursor.execute(
                '''
                SELECT
                    공격id,
                    발생시간,
                    요청구분,
                    공격유형,
                    대상엔드포인트,
                    "HTTP메서드"
                FROM 공격이벤트
                ORDER BY 발생시간 DESC
                LIMIT %s
                ''',
                (limit,)
            )

            rows = cursor.fetchall()

            return rows

    finally:
        conn.close()


def save_attacker_action(
    round_id,
    attack,
    attack_success,
    detected,
    reward
):
    """
    한 Battle Round에서 Attacker가 선택한 행동과
    그 결과/보상을 공격_AI_행동 테이블에 저장한다.
    """

    conn = get_connection()

    try:
        with conn.cursor() as cursor:

            cursor.execute(
                """
                INSERT INTO 공격AI행동 (
                    라운드id,
                    모델이름,
                    모델버전,
                    공격전략,
                    선택시나리오,
                    목표엔드포인트,
                    참고경험,
                    공격성공여부,
                    탐지회피여부,
                    보상점수
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s
                )
                RETURNING 행동id
                """,
                (
                    round_id,

                    attack.get(
                        "model",
                        "scenario-attacker"
                    ),

                    attack.get(
                        "version",
                        "v0.1"
                    ),

                    attack.get(
                        "attack_type"
                    ),

                    attack.get(
                        "scenario"
                    ),

                    attack.get(
                        "target"
                    ),

                    Json(
                        attack.get(
                            "experiences",
                            []
                        )
                    ),

                    attack_success,

                    # 탐지되지 않았으면 탐지 회피 성공
                    not detected,

                    reward
                )
            )

            action_id = cursor.fetchone()[0]

        conn.commit()

        return action_id

    except Exception as e:
        conn.rollback()

        print(
            "[DB ERROR - save_attacker_action]",
            str(e)
        )

        raise

    finally:
        conn.close()


def save_security_observation(observation):
    conn = get_connection()

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                '''
                INSERT INTO 공격이벤트 (
                    요청구분,
                    공격주체,
                    공격유형,
                    대상엔드포인트,
                    "HTTP메서드",
                    요청파라미터,
                    "HTTP상태코드",
                    "응답시간ms",
                    "요청로그"
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING 공격id
                ''',
                (
                    "NORMAL",              # 아직 공격이라고 단정 X
                    "USER",
                    None,
                    observation["endpoint"],
                    observation["method"],
                    Json({
                        "query": observation["query_params"],
                        "form": observation["form_params"],
                        "json": observation["json_body"]
                    }),
                    observation["http_status"],
                    round(observation["response_time_ms"]),
                    str(observation)
                )
            )

            event_id = cursor.fetchone()[0]

        conn.commit()
        return event_id

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

def create_battle_round(
    attacker_model,
    attacker_version,
    defender_model,
    defender_version
):
    conn = get_connection()

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO 대결라운드 (
                    공격자모델,
                    공격자버전,
                    방어자모델,
                    방어자버전
                )
                VALUES (%s, %s, %s, %s)
                RETURNING 라운드id
                """,
                (
                    attacker_model,
                    attacker_version,
                    defender_model,
                    defender_version
                )
            )

            round_id = cursor.fetchone()[0]

        conn.commit()
        return round_id

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

def finish_battle_round(
    round_id,
    event_id,
    result
):
    conn = get_connection()

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE 대결라운드
                SET
                    공격이벤트id = %s,
                    승자 = %s,
                    공격자보상 = %s,
                    방어자보상 = %s,
                    종료시간 = NOW()
                WHERE 라운드id = %s
                """,
                (
                    event_id,
                    result["winner"],
                    result["attacker_reward"],
                    result["defender_reward"],
                    round_id
                )
            )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

def save_evaluation_result(
    round_id,
    event_id,
    analysis_id,
    result
):
    conn = get_connection()

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                '''
                INSERT INTO "AI평가결과" (
                    라운드id,
                    공격id,
                    분석id,
                    탐지정확,
                    공격유형정확,
                    위험도정확,
                    "MITRE정확",
                    대응점수,
                    종합점수,
                    평가시간
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, NOW()
                )
                RETURNING 평가id
                ''',
                (
                    round_id,
                    event_id,
                    analysis_id,

                    # 현재 Evaluator에서 계산 가능
                    result["detection_correct"],
                    result["classification_correct"],

                    # 아직 Evaluator에서 평가하지 않는 항목
                    None,
                    None,

                    # 대응 평가도 아직 미구현
                    None,

                    # 임시 종합점수
                    calculate_total_score(result)
                )
            )

            evaluation_id = cursor.fetchone()[0]

        conn.commit()

        print(
            f"[EVALUATION SAVED] "
            f"evaluation={evaluation_id} "
            f"round={round_id}"
        )

        return evaluation_id

    except Exception as e:
        conn.rollback()
        print("[DB ERROR - save_evaluation_result]", str(e))
        raise

    finally:
        conn.close()

def calculate_total_score(result):
    """
    v0.1 임시 평가 점수

    탐지 정확도: 0.6
    공격 유형 분류 정확도: 0.4
    """

    score = 0.0

    if result["detection_correct"]:
        score += 0.6

    if result["classification_correct"]:
        score += 0.4

    return round(score, 4)     

def get_battle_stats():
    conn = get_connection()

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT
                    COUNT(*) AS total_battles,

                    COUNT(*) FILTER (
                        WHERE 승자 = 'ATTACKER'
                    ) AS attacker_wins,

                    COUNT(*) FILTER (
                        WHERE 승자 = 'DEFENDER'
                    ) AS defender_wins,

                    COUNT(*) FILTER (
                        WHERE 승자 = 'DRAW'
                    ) AS draws,

                    COALESCE(
                        AVG(공격자보상),
                        0
                    ) AS avg_attacker_reward,

                    COALESCE(
                        AVG(방어자보상),
                        0
                    ) AS avg_defender_reward

                FROM 대결라운드

                WHERE 종료시간 IS NOT NULL
                """
            )

            row = cursor.fetchone()

            return {
                "total_battles": row["total_battles"],
                "attacker_wins": row["attacker_wins"],
                "defender_wins": row["defender_wins"],
                "draws": row["draws"],
                "avg_attacker_reward": float(
                    row["avg_attacker_reward"]
                ),
                "avg_defender_reward": float(
                    row["avg_defender_reward"]
                )
            }

    finally:
        conn.close()


def get_battle_history(limit=100):
    conn = get_connection()

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                '''
                SELECT
                    r.라운드id, r.공격자모델, r.공격자버전, r.방어자모델, r.방어자버전,

                    a.공격전략,
                    a.선택시나리오,
                    a.목표엔드포인트,
                    a.공격성공여부,
                    a.탐지회피여부,

                    r.승자, r.공격자보상, r.방어자보상,

                    e.탐지정확,
                    e.공격유형정확,
                    e.위험도정확,
                    e."MITRE정확",
                    e.대응점수,
                    e.종합점수,

                    r.종료시간

                FROM 대결라운드 r

                LEFT JOIN "공격ai행동" a
                    ON r.라운드id = a.라운드id

                LEFT JOIN "AI평가결과" e
                    ON r.라운드id = e.라운드id

                WHERE r.종료시간 IS NOT NULL

                ORDER BY r.라운드id DESC

                LIMIT %s
                ''',
                (limit,)
            )

            rows = cursor.fetchall()

            results = []

            for row in rows:
                results.append({
                    "round_id": row["라운드id"],

                    "attacker_model": row["공격자모델"],
                    "attacker_version": row["공격자버전"],

                    "defender_model": row["방어자모델"],
                    "defender_version": row["방어자버전"],

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
                    ),

                    "defender_reward": (
                        float(row["방어자보상"])
                        if row["방어자보상"] is not None
                        else 0.0
                    ),

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

                    "finished_at": (
                        row["종료시간"].isoformat()
                        if row["종료시간"]
                        else None
                    )
                })

            return results

    finally:
        conn.close()


def save_rag_search_results(
    analysis_id,
    knowledge_type,
    results
):
    """
    RAG 검색 결과 여러 건을 RAG검색기록에 저장
    """

    if not results:
        return []

    conn = get_connection()
    search_ids = []

    try:
        with conn.cursor() as cursor:

            for rank, result in enumerate(results, start=1):

                # MITRE 문서 식별자
                document_id = (
                    result.get("technique_id")
                    or result.get("detection_id")
                    or result.get("analytic_id")
                    or f"UNKNOWN-{rank}"
                )

                # RAG가 실제 Defender에게 제공할 문서 내용
                document_content = (
                    f"Technique ID: {result.get('technique_id', '')}\n"
                    f"Technique: {result.get('technique_name', '')}\n"
                    f"Description: {result.get('description', '')}\n"
                    f"Tactics: {result.get('tactics', '')}\n"
                    f"Platforms: {result.get('platforms', '')}\n"
                    f"Mitigation: {result.get('mitigation', '')}\n"
                    f"Mitigation Description: "
                    f"{result.get('mitigation_description', '')}\n"
                    f"Detection ID: {result.get('detection_id', '')}\n"
                    f"Detection: {result.get('detection', '')}\n"
                    f"Analytic ID: {result.get('analytic_id', '')}\n"
                    f"Analytic: {result.get('analytic', '')}"
                )

                # 현재 v0.1 keyword 검색 score
                # 아직 embedding cosine similarity가 아님
                raw_score = result.get("score", 0)

                # DB 유사도는 0~1 범위로 임시 정규화
                similarity = min(
                    float(raw_score) / 5.0,
                    1.0
                )

                cursor.execute(
                    '''
                    INSERT INTO "RAG검색기록" (
                        분석id, 지식유형, 문서id, 문서내용, 유사도, 검색순위, 검색시간
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, NOW()
                    )
                    RETURNING 검색id
                    ''',
                    (
                        analysis_id,
                        knowledge_type,
                        document_id,
                        document_content,
                        similarity,
                        rank
                    )
                )

                search_id = cursor.fetchone()[0]
                search_ids.append(search_id)

        conn.commit()

        print(
            f"[RAG SEARCH SAVED] "
            f"analysis={analysis_id} "
            f"type={knowledge_type} "
            f"documents={len(search_ids)}"
        )

        return search_ids

    except Exception as e:
        conn.rollback()
        print("[DB ERROR - save_rag_search_results]", str(e))
        raise

    finally:
        conn.close()


