# rag/system_rag.py

import json
import os


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

JSON_PATH = os.path.join(
    BASE_DIR,
    "data",
    "banking_system_info.json"
)

_system_data = None


def load_system_data():
    global _system_data

    if _system_data is None:

        with open(
            JSON_PATH,
            "r",
            encoding="utf-8"
        ) as f:
            _system_data = json.load(f)

        print("[SYSTEM RAG] banking system knowledge loaded")

    return _system_data


def _normalize_key(key):
    return (
        str(key)
        .lower()
        .replace("_", "")
        .replace("-", "")
        .replace(" ", "")
        .replace("&", "")
    )


def _flatten_safe_system_knowledge(data):

    root = data.get(
        "banking_system_info",
        data
    )

    documents = []

    # Defender에게 절대 노출하면 안 되는 key 패턴
    blocked_patterns = [
        "vulnerabilit",
        "exploit",
        "groundtruth"
    ]

    for key, value in root.items():

        normalized_key = _normalize_key(key)

        # ---------------------------------------
        # 취약점 / Ground Truth 정보 차단
        # ---------------------------------------
        if any(
            pattern in normalized_key
            for pattern in blocked_patterns
        ):
            print(
                f"[SYSTEM RAG FILTER] "
                f"blocked={repr(key)} "
                f"normalized={normalized_key}"
            )
            continue

        # ---------------------------------------
        # 안전한 시스템 정보만 Document 생성
        # ---------------------------------------
        if isinstance(value, (dict, list)):
            content = json.dumps(
                value,
                ensure_ascii=False
            )
        else:
            content = str(value)

        documents.append({
            "document_id": f"SYSTEM-{key}",
            "category": "SYSTEM_INFO",
            "title": str(key),
            "content": content
        })

    return documents

def search_system(
    query,
    top_k=3
):
    """
    v0.1 keyword 기반 SYSTEM RAG
    """

    data = load_system_data()

    documents = _flatten_safe_system_knowledge(
        data
    )

    query = query.lower().strip()

    if not query:
        return []

    keywords = [
        word
        for word in query.split()
        if len(word) >= 2
    ]

    results = []

    for document in documents:

        text = (
            f"{document['title']} "
            f"{document['content']}"
        ).lower()

        score = 0

        for keyword in keywords:

            if keyword in text:
                score += 1

        if score > 0:

            results.append({
                "score": score,
                "document_id": document[
                    "document_id"
                ],
                "category": document[
                    "category"
                ],
                "title": document[
                    "title"
                ],
                "content": document[
                    "content"
                ]
            })

    results.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    return results[:top_k]