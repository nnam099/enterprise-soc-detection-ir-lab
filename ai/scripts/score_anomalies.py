#!/usr/bin/env python3

import argparse
from pathlib import Path

import joblib
import pandas as pd


IDENTIFIER_COLUMNS = [
    "timestamp",
    "hunt_id",
    "source_file",
    "event_category",
    "rule_id",
    "event_id_raw",
    "agent",
    "computer",
    "user",
]


def main():
    parser = argparse.ArgumentParser(
        description="Score SOC-LAB timeline events with Isolation Forest."
    )

    parser.add_argument(
        "--input",
        default="ai/features/DFIR-001-features.csv",
    )

    parser.add_argument(
        "--model",
        default="ai/models/isolation_forest.joblib",
    )

    parser.add_argument(
        "--output",
        default="ai/results/DFIR-001-anomaly-scores.csv",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    model_path = Path(args.model)
    output_path = Path(args.output)

    if not input_path.exists():
        raise SystemExit(
            f"[!] Feature file not found: {input_path}"
        )

    if not model_path.exists():
        raise SystemExit(
            f"[!] Model not found: {model_path}"
        )

    df = pd.read_csv(input_path)

    package = joblib.load(model_path)

    model = package["model"]
    features = package["features"]

    missing = [
        f for f in features
        if f not in df.columns
    ]

    if missing:
        raise SystemExit(
            "[!] Missing required features: "
            + ", ".join(missing)
        )

    X = (
        df[features]
        .apply(pd.to_numeric, errors="coerce")
        .fillna(0)
    )

    #
    # sklearn:
    #
    # decision_function:
    #   positive -> more normal
    #   negative -> more anomalous
    #
    # We invert it so larger anomaly_score means
    # "more anomalous", which is easier for analysts.
    #
    raw_score = model.decision_function(X)

    prediction = model.predict(X)

    result = df[
        [
            col
            for col in IDENTIFIER_COLUMNS
            if col in df.columns
        ]
    ].copy()

    result["rule_level"] = df["rule_level"]

    result["anomaly_score"] = -raw_score

    result["is_anomaly"] = (
        prediction == -1
    ).astype(int)

    result["analyst_priority"] = result.apply(
        lambda row:
            "HIGH"
            if row["is_anomaly"] == 1
            and row["rule_level"] >= 8
            else (
                "MEDIUM"
                if row["is_anomaly"] == 1
                else "NORMAL"
            ),
        axis=1,
    )

    result = result.sort_values(
        by="anomaly_score",
        ascending=False,
    )

    result.insert(
        0,
        "anomaly_rank",
        range(1, len(result) + 1),
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    result.to_csv(
        output_path,
        index=False,
    )

    print("[+] Anomaly scoring complete")
    print(f"[+] Events : {len(result)}")
    print(
        f"[+] Anomalies: "
        f"{int(result['is_anomaly'].sum())}"
    )
    print(f"[+] Output : {output_path}")

    print("\n[+] Ranked events:\n")

    display_columns = [
        "anomaly_rank",
        "hunt_id",
        "event_category",
        "rule_id",
        "rule_level",
        "anomaly_score",
        "is_anomaly",
        "analyst_priority",
    ]

    print(
        result[display_columns]
        .to_string(index=False)
    )


if __name__ == "__main__":
    main()
