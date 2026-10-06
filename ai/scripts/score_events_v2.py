#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

import joblib

from build_feature_matrix_v2 import load_rows

def main():
    parser = argparse.ArgumentParser(description="Score normalized SOC-LAB Windows events with Isolation Forest v2.")
    parser.add_argument("input")
    parser.add_argument("vectorizer")
    parser.add_argument("model")
    parser.add_argument("manifest")
    parser.add_argument("output")
    parser.add_argument("--report")
    args = parser.parse_args()

    rows, metadata = load_rows(args.input)
    if not rows:
        raise SystemExit("No usable events found.")

    vectorizer = joblib.load(args.vectorizer)
    model = joblib.load(args.model)

    with open(args.manifest, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    threshold = float(manifest["threshold"])

    X = vectorizer.transform(rows)
    scores = model.score_samples(X)

    anomalies = 0
    results = []

    for meta, score in zip(metadata, scores):
        is_anomaly = bool(score < threshold)
        anomalies += int(is_anomaly)
        row = dict(meta)
        row["score"] = float(score)
        row["threshold"] = threshold
        row["is_anomaly"] = is_anomaly
        row["margin_to_threshold"] = float(score - threshold)
        results.append(row)

    with open(args.output, "w", encoding="utf-8") as f:
        for row in results:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")

    report = {
        "events": len(results),
        "anomalies": anomalies,
        "anomaly_rate": anomalies / len(results),
        "threshold": threshold,
        "score_min": float(scores.min()),
        "score_mean": float(scores.mean()),
        "score_max": float(scores.max()),
        "matrix_shape": [int(X.shape[0]), int(X.shape[1])],
    }

    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

    print(json.dumps(report, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
