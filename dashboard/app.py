import os
import requests
import pandas as pd
import streamlit as st


# ============================================================
# CONFIG
# ============================================================

st.set_page_config(
    page_title="AI Cyber Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

FLASK_URL = os.getenv(
    "FLASK_URL",
    "http://127.0.0.1:5000"
)


# ============================================================
# API
# ============================================================

def api_get(path):
    response = requests.get(
        f"{FLASK_URL}{path}",
        timeout=10
    )
    response.raise_for_status()
    return response.json()


def api_post(path):
    response = requests.post(
        f"{FLASK_URL}{path}",
        timeout=300
    )
    response.raise_for_status()
    return response.json()


# ============================================================
# CSS
# ============================================================

st.markdown(
    """
    <style>

    /* 전체 폭 */
    .block-container {
        max-width: 1450px;
        padding-top: 2.2rem;
        padding-bottom: 4rem;
    }

    /* 기본 배경 */
    .stApp {
        background: #ffffff;
    }

    /* 헤더 */
    .main-title {
        font-size: 2.1rem;
        font-weight: 750;
        letter-spacing: -0.04em;
        color: #111827;
        margin: 0;
    }

    .subtitle {
        color: #6b7280;
        font-size: 0.93rem;
        margin-top: 0.3rem;
    }

    /* section */
    .section-label {
        color: #6b7280;
        font-size: 0.73rem;
        font-weight: 700;
        letter-spacing: 0.10em;
        margin-bottom: 0.35rem;
    }

    /* AI 이름 */
    .agent-name {
        font-size: 0.82rem;
        font-weight: 700;
        color: #374151;
        letter-spacing: 0.04em;
    }

    .attacker-value {
        color: #be123c;
        font-size: 1.55rem;
        font-weight: 750;
        letter-spacing: -0.03em;
        margin-top: 0.45rem;
    }

    .defender-value {
        color: #1d4ed8;
        font-size: 1.55rem;
        font-weight: 750;
        letter-spacing: -0.03em;
        margin-top: 0.45rem;
    }

    .agent-meta {
        color: #6b7280;
        font-size: 0.82rem;
        line-height: 1.8;
        margin-top: 0.5rem;
    }

    /* VS */
    .vs {
        text-align: center;
        color: #9ca3af;
        font-weight: 700;
        font-size: 0.8rem;
        padding-top: 3.3rem;
        letter-spacing: 0.08em;
    }

    /* 승자 */
    .winner {
        text-align: center;
        font-size: 1.05rem;
        font-weight: 750;
        color: #111827;
        padding: 0.5rem;
    }

    /* 작은 상태 */
    .status-line {
        color: #374151;
        font-size: 0.84rem;
        line-height: 2;
    }

    .online-dot {
        color: #16a34a;
        font-size: 0.75rem;
    }

    /* history */
    .history-title {
        font-size: 0.88rem;
        font-weight: 650;
        color: #111827;
    }

    .history-meta {
        color: #6b7280;
        font-size: 0.77rem;
    }

    /* divider 여백 줄이기 */
    hr {
        margin-top: 1.4rem !important;
        margin-bottom: 1.4rem !important;
        border-color: #e5e7eb !important;
    }

    /* metric */
    [data-testid="stMetric"] {
        background: transparent;
    }

    [data-testid="stMetricLabel"] {
        color: #6b7280;
    }

    [data-testid="stMetricValue"] {
        font-size: 1.55rem;
        color: #111827;
    }

    /* 버튼 */
    .stButton > button {
        border-radius: 8px;
        height: 2.8rem;
        font-weight: 650;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# DATA
# ============================================================

backend_online = False
battles = []
stats = {}

try:
    health = api_get("/api/health")
    backend_online = health.get("status") == "online"
except Exception:
    backend_online = False


try:
    history_data = api_get("/api/battles/history")
    battles = history_data.get("history", [])

    # 중복 round 제거
    unique = {}

    for battle in battles:
        round_id = battle.get("round_id")

        if round_id not in unique:
            unique[round_id] = battle

    battles = list(unique.values())

    battles.sort(
        key=lambda x: x.get("round_id", 0),
        reverse=True
    )

except Exception:
    battles = []


try:
    stats = api_get("/api/battles/stats")
except Exception:
    stats = {}


# ============================================================
# HEADER
# ============================================================

header_left, header_right = st.columns(
    [5, 1.3],
    vertical_alignment="center"
)

with header_left:

    st.markdown(
        '<div class="main-title">AI Cyber Defense</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <div class="subtitle">
        Adversarial AI Security · Self-Play Defense · RAG Experience
        </div>
        """,
        unsafe_allow_html=True
    )


with header_right:

    if backend_online:
        st.success("Vuln-bank 시스템 운영중")
    else:
        st.error("Vuln-bank 시스템 미가동중")


st.divider()


# ============================================================
# TOP METRICS
# ============================================================

total_battles = len(battles)

defender_wins = sum(
    1 for b in battles
    if b.get("winner") == "DEFENDER"
)

attacker_wins = sum(
    1 for b in battles
    if b.get("winner") == "ATTACKER"
)

evaluated = [
    b for b in battles
    if b.get("detection_correct") is not None
]

correct_detection = sum(
    1 for b in evaluated
    if b.get("detection_correct") is True
)

detection_rate = (
    correct_detection / len(evaluated) * 100
    if evaluated
    else 0
)

total_defender_reward = sum(
    float(b.get("defender_reward") or 0)
    for b in battles
)


m1, m2, m3, m4 = st.columns(4)

with m1:
    st.metric(
        "Battle Rounds",
        total_battles
    )

with m2:
    st.metric(
        "Detection Accuracy",
        f"{detection_rate:.0f}%"
    )

with m3:
    st.metric(
        "Defender Wins",
        defender_wins
    )

with m4:
    st.metric(
        "Defender Reward",
        f"{total_defender_reward:+.1f}"
    )


st.divider()


# ============================================================
# BATTLE CONTROL
# ============================================================

control_left, control_right = st.columns(
    [4, 1]
)

with control_left:

    st.markdown(
        '<div class="section-label">ADVERSARIAL SELF-PLAY</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        "### Live AI Battle"
    )


with control_right:

    if st.button(
        "Run AI Battle",
        use_container_width=True,
        type="primary",
        disabled=not backend_online
    ):

        with st.spinner(
            "Attacker AI와 Defender AI가 대결 중입니다..."
        ):

            try:
                api_post("/api/attack")

                st.success(
                    "Battle completed"
                )

                st.rerun()

            except Exception as e:

                st.error(
                    f"Battle 실행 오류: {e}"
                )


# ============================================================
# LATEST BATTLE
# ============================================================

if battles:

    latest = battles[0]

    round_id = latest.get("round_id", "-")
    attack_type = latest.get("attack_type", "-")
    scenario = latest.get("scenario", "-")
    target = latest.get("target", "-")

    attacker_model = latest.get(
        "attacker_model",
        "-"
    )

    attacker_version = latest.get(
        "attacker_version",
        "-"
    )

    defender_model = latest.get(
        "defender_model",
        "-"
    )

    defender_version = latest.get(
        "defender_version",
        "-"
    )

    winner = latest.get("winner", "-")

    attacker_reward = float(
        latest.get("attacker_reward") or 0
    )

    defender_reward = float(
        latest.get("defender_reward") or 0
    )

    attack_success = latest.get(
        "attack_success"
    )

    detection_correct = latest.get(
        "detection_correct"
    )

    classification_correct = latest.get(
        "classification_correct"
    )


    st.caption(
        f"Battle #{round_id}"
    )

    attacker_col, vs_col, defender_col = st.columns(
        [5, 1, 5]
    )


    # --------------------------------------------------------
    # ATTACKER
    # --------------------------------------------------------

    st.markdown("""
            <style>

            /* Battle 전체 */
            .battle-panel {
                border: 1px solid #e5e7eb;
                border-radius: 16px;
                padding: 28px 34px;
                background: #ffffff;
            }

            /* Agent label */
            .agent-label {
                font-size: 12px;
                font-weight: 700;
                letter-spacing: .09em;
                color: #6b7280;
                margin-bottom: 12px;
            }

            /* 공격 */
            .attack-title {
                font-size: 28px;
                font-weight: 750;
                color: #be123c;
                letter-spacing: -.03em;
                margin-bottom: 18px;
            }

            /* 방어 */
            .defense-title {
                font-size: 28px;
                font-weight: 750;
                color: #1d4ed8;
                letter-spacing: -.03em;
                margin-bottom: 18px;
            }

            /* 상세정보 */
            .battle-info {
                font-size: 14px;
                line-height: 1.9;
                color: #4b5563;
            }

            .battle-info b {
                color: #111827;
            }

            /* VS */
            .battle-vs {
                text-align: center;
                font-size: 16px;
                font-weight: 800;
                color: #9ca3af;
                padding-top: 55px;
            }

            /* 결과 */
            .result-title {
                text-align: center;
                font-size: 18px;
                font-weight: 800;
                color: #111827;
            }

            /* reward */
            .reward-value {
                font-size: 24px;
                font-weight: 700;
                color: #111827;
            }

            .reward-label {
                font-size: 12px;
                color: #6b7280;
                margin-bottom: 3px;
            }

            </style>
            """, unsafe_allow_html=True)
    
    with attacker_col:

        st.markdown(
            '<div class="agent-name">ATTACKER AI</div>',
            unsafe_allow_html=True
        )

        st.markdown(
            f'<div class="attacker-value">{attack_type}</div>',
            unsafe_allow_html=True
        )

        st.markdown(
            f"""
            <div class="agent-meta">
                Model &nbsp; {attacker_model} {attacker_version}<br>
                Target &nbsp; {target}<br>
                Scenario &nbsp; {scenario}
            </div>
            """,
            unsafe_allow_html=True
        )


    # --------------------------------------------------------
    # VS
    # --------------------------------------------------------

    with vs_col:

        st.markdown(
            '<div class="vs">VS</div>',
            unsafe_allow_html=True
        )


    # --------------------------------------------------------
    # DEFENDER
    # --------------------------------------------------------

    with defender_col:

        st.markdown(
            '<div class="agent-name">DEFENDER AI</div>',
            unsafe_allow_html=True
        )

        if detection_correct is True:
            decision_text = "ATTACK DETECTED"
        elif detection_correct is False:
            decision_text = "MISSED"
        else:
            decision_text = "ANALYZED"

        st.markdown(
            f'<div class="defender-value">{decision_text}</div>',
            unsafe_allow_html=True
        )

        st.markdown(
            f"""
            <div class="agent-meta">
                Model &nbsp; {defender_model} {defender_version}<br>
                Detection &nbsp; {
                    "Correct"
                    if detection_correct is True
                    else "Incorrect"
                    if detection_correct is False
                    else "-"
                }<br>
                Classification &nbsp; {
                    "Correct"
                    if classification_correct is True
                    else "Incorrect"
                    if classification_correct is False
                    else "-"
                }
            </div>
            """,
            unsafe_allow_html=True
        )


    st.write("")

    if winner == "DEFENDER":
        st.markdown(
            '<div class="winner">DEFENDER WIN</div>',
            unsafe_allow_html=True
        )

    elif winner == "ATTACKER":
        st.markdown(
            '<div class="winner">ATTACKER WIN</div>',
            unsafe_allow_html=True
        )

    else:
        st.markdown(
            '<div class="winner">DRAW</div>',
            unsafe_allow_html=True
        )


    reward_left, reward_mid, reward_right = st.columns(
        [2, 1, 2]
    )

    with reward_left:
        st.metric(
            "Attacker Reward",
            f"{attacker_reward:+.1f}"
        )

    with reward_mid:
        st.markdown("")

    with reward_right:
        st.metric(
            "Defender Reward",
            f"{defender_reward:+.1f}"
        )


else:

    st.info(
        "Battle을 실행하면 Attacker AI와 Defender AI의 "
        "대결 결과가 여기에 표시됩니다."
    )


st.divider()


# ============================================================
# PERFORMANCE + EVOLUTION
# ============================================================

performance_col, evolution_col = st.columns(
    [3, 2],
    gap="large"
)


# ------------------------------------------------------------
# REWARD EVOLUTION
# ------------------------------------------------------------

with performance_col:

    st.markdown(
        '<div class="section-label">PERFORMANCE</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        "### Reward Evolution"
    )

    chart_battles = list(
        reversed(battles[:15])
    )

    if chart_battles:

        chart_data = pd.DataFrame({
            "Battle": [
                b.get("round_id")
                for b in chart_battles
            ],
            "Attacker": [
                float(
                    b.get("attacker_reward") or 0
                )
                for b in chart_battles
            ],
            "Defender": [
                float(
                    b.get("defender_reward") or 0
                )
                for b in chart_battles
            ]
        })

        chart_data = chart_data.set_index(
            "Battle"
        )

        st.line_chart(
            chart_data,
            height=300
        )

    else:

        st.info(
            "Reward 데이터가 없습니다."
        )


# ------------------------------------------------------------
# ADVERSARIAL EVOLUTION
# ------------------------------------------------------------

with evolution_col:

    st.markdown(
        '<div class="section-label">LEARNING LOOP</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        "### Adversarial Evolution"
    )

    for battle in battles[:5]:

        round_id = battle.get(
            "round_id",
            "-"
        )

        attack_type = battle.get(
            "attack_type",
            "-"
        )

        winner = battle.get(
            "winner",
            "-"
        )

        reward = float(
            battle.get(
                "defender_reward"
            ) or 0
        )

        st.markdown(
            f"""
            <div class="history-title">
                Battle #{round_id}
            </div>
            <div class="history-meta">
                {attack_type}
                &nbsp; · &nbsp;
                {winner}
                &nbsp; · &nbsp;
                Defender {reward:+.1f}
            </div>
            """,
            unsafe_allow_html=True
        )

        st.write("")


st.divider()


# ============================================================
# BATTLE HISTORY
# ============================================================

st.markdown(
    '<div class="section-label">RECENT ACTIVITY</div>',
    unsafe_allow_html=True
)

st.markdown(
    "### Battle History"
)


if battles:

    history_rows = []

    for battle in battles[:10]:

        detection = battle.get(
            "detection_correct"
        )

        classification = battle.get(
            "classification_correct"
        )

        history_rows.append({
            "Battle": f"#{battle.get('round_id')}",
            "Attack": battle.get(
                "attack_type"
            ),
            "Target": battle.get(
                "target"
            ),
            "Winner": battle.get(
                "winner"
            ),
            "Detection": (
                "Correct"
                if detection is True
                else "Incorrect"
                if detection is False
                else "-"
            ),
            "Classification": (
                "Correct"
                if classification is True
                else "Incorrect"
                if classification is False
                else "-"
            ),
            "Attacker Reward": float(
                battle.get(
                    "attacker_reward"
                ) or 0
            ),
            "Defender Reward": float(
                battle.get(
                    "defender_reward"
                ) or 0
            )
        })


    history_df = pd.DataFrame(
        history_rows
    )

    st.dataframe(
        history_df,
        use_container_width=True,
        hide_index=True,
        height=390
    )

else:

    st.info(
        "Battle 기록이 없습니다."
    )