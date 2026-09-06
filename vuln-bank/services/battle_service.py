# services/battle_service.py

from ai_attacker.agent import select_attack
from ai_defender.agent import analyze_observation
from evaluator.evaluator import evaluate_battle
from services.scenario_service import execute_scenario

from rag.system_rag import search_system
from rag.mitre_rag import search_mitre
from rag.experience_rag import (
    search_attacker_experience,
    search_defender_experience
)

from db_work.cyber_db import (
    create_battle_round,
    finish_battle_round,
    save_attacker_action,
    save_defense_result,
    save_evaluation_result,
    save_rag_search_results
)


def run_battle():

    print("\n========== AI BATTLE START ==========")

    attacker_experience = search_attacker_experience(
    limit=3
)

    print(
        f"[ATTACKER EXPERIENCE] "
        f"results={len(attacker_experience)}"
    )


    # ==================================================
    # 1. Attacker AI
    # 공격 시나리오 선택
    # ==================================================

    attack = select_attack(
        experience_context=attacker_experience
    )

    print(
        f"[ATTACKER AI] "
        f"model={attack['model']} "
        f"scenario={attack['scenario']} "
        f"attack={attack['attack_type']} "
        f"target={attack['target']}"
    )

    print(
        f"[ATTACKER REASON] "
        f"{attack.get('reason')}"
    )


    print(
        f"[ATTACKER] "
        f"model={attack['model']} "
        f"version={attack['version']} "
        f"attack={attack['attack_type']} "
        f"scenario={attack['scenario']} "
        f"target={attack['target']}"
    )


    # ==================================================
    # 2. Battle Round 생성
    # ==================================================

    round_id = create_battle_round(
        attacker_model=attack["model"],
        attacker_version=attack["version"],
        defender_model="rule-defender",
        defender_version="v0.2"
    )

    print(
        f"[BATTLE CREATED] "
        f"round={round_id}"
    )


    # ==================================================
    # 3. Environment / Scenario 실행
    #
    # execute_scenario() 내부에서:
    #
    # - 보안이벤트 저장
    # - Ground Truth 저장
    #
    # 이뤄지고 있으므로 여기서 다시 저장하면 안 됨.
    # ==================================================

    environment = execute_scenario(attack)

    event_id = environment["event_id"]
    observation = environment["observation"]
    attack_success = environment["attack_success"]
    ground_truth = environment["ground_truth"]

    print(
        f"[ENVIRONMENT] "
        f"event={event_id} "
        f"attack_success={attack_success}"
    )


    # ==================================================
    # 4. RAG Query 생성
    #
    # 매우 중요:
    #
    # Defender가 볼 수 있는 Observation만 사용한다.
    #
    # attack["attack_type"]
    # ground_truth
    #
    # 등을 넣으면 정답 누출이 발생한다.
    # ==================================================

    rag_query_parts = [
    str(observation.get("method", "")),
    str(observation.get("endpoint", "")),
    f"status {observation.get('http_status', '')}"
]


    # Query Parameters
    query_params = observation.get(
        "query_params",
        {}
    )

    if query_params:
        rag_query_parts.append(
            f"query parameters {query_params}"
        )


    # Form Parameters
    form_params = observation.get(
        "form_params",
        {}
    )

    if form_params:
        rag_query_parts.append(
            f"form parameters {form_params}"
        )


    # JSON Body
    json_body = observation.get(
        "json_body"
    )

    if json_body:
        rag_query_parts.append(
            f"json body {json_body}"
        )


    # 추가 관측 Feature
    if observation.get(
        "recent_login_failures"
    ) is not None:

        rag_query_parts.append(
            f"recent login failures "
            f"{observation['recent_login_failures']}"
        )


    rag_query = " ".join(
        rag_query_parts
    )


    # 관측 가능한 추가 Feature가 있으면 포함
    if observation.get("recent_login_failures") is not None:
        rag_query_parts.append(
            f"recent login failures "
            f"{observation['recent_login_failures']}"
        )

    rag_query = " ".join(rag_query_parts)

    print(
        f"[RAG QUERY] "
        f"{rag_query}"
    )


    # ==================================================
    # 5. SYSTEM RAG
    #
    # banking_system_info.json 기반
    #
    # Implemented Vulnerabilities는
    # system_rag.py에서 차단되어 있어야 한다.
    # ==================================================

    system_results = search_system(
        query=rag_query,
        top_k=1
    )

    print(
        f"[SYSTEM RAG] "
        f"query={rag_query} "
        f"results={len(system_results)}"
    )

    for result in system_results:
        print(
            f"  -> "
            f"{result.get('document_id')} "
            f"score={result.get('score')}"
        )


    # ==================================================
    # 6. MITRE ATT&CK RAG
    # ==================================================

    mitre_results = search_mitre(
        query=rag_query,
        top_k=1
    )

    print(
        f"[MITRE RAG] "
        f"query={rag_query} "
        f"results={len(mitre_results)}"
    )

    for result in mitre_results:
        print(
            f"  -> "
            f"{result.get('technique_id')} "
            f"{result.get('technique_name')} "
            f"score={result.get('score')}"
        )


    # ==================================================
    # 7. EXPERIENCE RAG
    #
    # PostgreSQL에 저장된 과거 Battle 중
    # 현재 Observation과 비슷한 경험 검색
    # ==================================================

    experience_results = search_defender_experience(
        observation=observation,
        limit=1
    )

    print(
        f"[EXPERIENCE RAG] "
        f"results={len(experience_results)}"
    )

    for result in experience_results:
        print(
            f"  -> "
            f"{result.get('document_id')} "
            f"score={result.get('score')}"
        )


    # ==================================================
    # 8. Defender용 RAG Context 구성
    # ==================================================

    rag_context = {
        "system": system_results,
        "mitre": mitre_results,
        "experience": experience_results
    }


    # ==================================================
    # 9. Defender AI 분석
    #
    # Ground Truth는 전달하지 않는다.
    #
    # Defender가 볼 수 있는 것은:
    #
    # Observation
    # SYSTEM RAG
    # MITRE RAG
    # EXPERIENCE RAG
    #
    # 뿐이다.
    # ==================================================

    defense = analyze_observation(
        observation=observation,
        rag_context=rag_context
    )

    print(
        f"[DEFENDER] "
        f"detected={defense['detected']} "
        f"prediction={defense['attack_type']} "
        f"confidence={defense['confidence']}"
    )


    # ==================================================
    # 10. Defender 분석 결과 저장
    # ==================================================

    analysis_id = save_defense_result(
        event_id,
        defense
    )

    print(
        f"[DEFENSE SAVED] "
        f"analysis={analysis_id}"
    )


    # ==================================================
    # 11. RAG 검색 Provenance 저장
    #
    # analysis_id가 필요하기 때문에
    # 실제 검색은 Defender 전에 하지만
    # DB 기록은 분석 저장 이후에 한다.
    # ==================================================

    save_rag_search_results(
        analysis_id=analysis_id,
        knowledge_type="SYSTEM",
        results=system_results
    )

    save_rag_search_results(
        analysis_id=analysis_id,
        knowledge_type="MITRE",
        results=mitre_results
    )

    save_rag_search_results(
        analysis_id=analysis_id,
        knowledge_type="EXPERIENCE",
        results=experience_results
    )


    # ==================================================
    # 12. Evaluator
    #
    # 여기서 처음 Ground Truth와
    # Defender Prediction을 비교한다.
    # ==================================================

    result = evaluate_battle(
        ground_truth=ground_truth,
        defense=defense,
        attack_success=attack_success
    )

    print(
        f"[EVALUATOR] "
        f"winner={result['winner']} "
        f"attacker_reward={result['attacker_reward']} "
        f"defender_reward={result['defender_reward']} "
        f"detection_correct={result['detection_correct']} "
        f"classification_correct="
        f"{result['classification_correct']}"
    )


    # ==================================================
    # 13. Attacker 행동/Reward 저장
    # ==================================================

    save_attacker_action(
        round_id=round_id,
        attack=attack,
        attack_success=attack_success,
        detected=defense["detected"],
        reward=result["attacker_reward"]
    )


    # ==================================================
    # 14. AI 평가 결과 저장
    # ==================================================

    evaluation_id = save_evaluation_result(
        round_id=round_id,
        event_id=event_id,
        analysis_id=analysis_id,
        result=result
    )


    # ==================================================
    # 15. Battle Round 종료
    # ==================================================

    finish_battle_round(
        round_id=round_id,
        event_id=event_id,
        result=result
    )


    # ==================================================
    # 16. 최종 로그
    # ==================================================

    print(
        f"[BATTLE RESULT] "
        f"round={round_id} "
        f"winner={result['winner']} "
        f"A={result['attacker_reward']} "
        f"D={result['defender_reward']}"
    )

    print(
        "========== AI BATTLE END ==========\n"
    )


    # ==================================================
    # 17. Flask API 반환
    # ==================================================

    return {
        "round_id": round_id,
        "event_id": event_id,
        "analysis_id": analysis_id,
        "evaluation_id": evaluation_id,

        "attack": attack,

        "observation": observation,

        "rag": {
            "system": system_results,
            "mitre": mitre_results,
            "experience": experience_results
        },

        "defense": defense,

        "result": result
    }