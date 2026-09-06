import os
import pandas as pd


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

CSV_PATH = os.path.join(
    BASE_DIR,
    "data",
    "security_map.csv"
)


_mitre_df = None


def load_mitre_data():

    global _mitre_df

    if _mitre_df is None:

        _mitre_df = pd.read_csv(
            CSV_PATH
        )

        _mitre_df = _mitre_df.fillna("")

        print(
            f"[MITRE RAG] "
            f"loaded={len(_mitre_df)}"
        )

    return _mitre_df

def search_mitre(
    query,
    top_k=3
):
    df = load_mitre_data()

    query = query.lower().strip()

    if not query:
        return []

    search_columns = [
        "target ID",
        "target name",
        "tech_name",
        "tech_description",
        "tactics",
        "platforms",
        "miti_name",
        "miti_description",
        "anal_name",
        "anal_description",
        "detect_name"
    ]

    results = []

    for index, row in df.iterrows():

        score = 0

        searchable_text = []

        for column in search_columns:

            if column in df.columns:

                value = str(
                    row[column]
                )

                searchable_text.append(
                    value
                )

        text = " ".join(
            searchable_text
        ).lower()

        # v0.1 keyword matching
        for keyword in query.split():

            if keyword in text:
                score += 1

        if score > 0:

            results.append(
                {
                    "score": score,

                    "technique_id": row.get(
                        "target ID",
                        ""
                    ),

                    "technique_name": row.get(
                        "target name",
                        ""
                    ),

                    "technique": row.get(
                        "tech_name",
                        ""
                    ),

                    "description": row.get(
                        "tech_description",
                        ""
                    ),

                    "tactics": row.get(
                        "tactics",
                        ""
                    ),

                    "platforms": row.get(
                        "platforms",
                        ""
                    ),

                    "mitigation": row.get(
                        "miti_name",
                        ""
                    ),

                    "mitigation_description": row.get(
                        "miti_description",
                        ""
                    ),

                    "detection_id": row.get(
                        "detect_ID",
                        ""
                    ),

                    "detection": row.get(
                        "detect_name",
                        ""
                    ),

                    "analytic_id": row.get(
                        "anal_ID",
                        ""
                    ),

                    "analytic": row.get(
                        "anal_name",
                        ""
                    )
                }
            )

    results.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    return results[:top_k]

