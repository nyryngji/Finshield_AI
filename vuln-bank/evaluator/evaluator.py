def evaluate_battle(
    ground_truth,
    defense,
    attack_success
):
    """
    한 번의 Attack-Defense 대결 결과를 평가한다.

    LLM의 자기평가가 아니라
    Ground Truth + 시스템 결과를 기반으로 평가한다.
    """

    is_attack = ground_truth["is_attack"]
    true_type = ground_truth.get("attack_type")

    detected = defense["detected"]
    predicted_type = defense["attack_type"]

    attacker_reward = 0.0
    defender_reward = 0.0

    # 정상 요청
    if not is_attack:

        if detected:
            # False Positive
            defender_reward -= 1.0
            winner = "ATTACKER"

        else:
            defender_reward += 1.0
            winner = "DEFENDER"

        return {
            "winner": winner,
            "attacker_reward": attacker_reward,
            "defender_reward": defender_reward,
            "detection_correct": not detected,
            "classification_correct": predicted_type == "NORMAL"
        }

    # 공격 성공 + 탐지 실패
    if attack_success and not detected:
        attacker_reward += 2.0
        defender_reward -= 2.0

    # 공격 탐지 성공
    if detected:
        defender_reward += 1.0
        attacker_reward -= 0.5

    # 공격 유형까지 정확하게 분류
    classification_correct = (
        detected and
        predicted_type == true_type
    )

    if classification_correct:
        defender_reward += 0.5

    # 공격 자체가 실패
    if not attack_success:
        defender_reward += 0.5
        attacker_reward -= 0.5

    if defender_reward > attacker_reward:
        winner = "DEFENDER"

    elif attacker_reward > defender_reward:
        winner = "ATTACKER"

    else:
        winner = "DRAW"

    return {
        "winner": winner,

        "attacker_reward": attacker_reward,
        "defender_reward": defender_reward,

        "detection_correct": detected,
        "classification_correct": classification_correct
    }