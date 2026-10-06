#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np

from build_feature_matrix_v3 import load_rows


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description="Score normalized SOC-LAB Windows events with Isolation Forest v3."
    )
    parser.add_argument("input_jsonl")
    parser.add_argument("vectorizer")
    parser.add_argument("model")
    parser.add_argument("manifest")
    parser.add_argument("output_jsonl")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()

    input_path = Path(args.input_jsonl)
    vectorizer_path = Path(args.vectorizer)
    model_path = Path(args.model)
    manifest_path = Path(args.manifest)
    output_path = Path(args.output_jsonl)
    report_path = Path(args.report)

    rows, metadata = load_rows(input_path)
    if not rows:
        raise SystemExit("No events were loaded from input.")

    vectorizer = joblib.load(vectorizer_path)
    model = joblib.load(model_path)

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    threshold = float(manifest["threshold"])

    X = vectorizer.transform(rows)

    expected_features = getattr(model, "n_features_in_", None)
    if expected_features is not None and X.shape[1] != int(expected_features):
        raise SystemExit(
            f"Feature mismatch: matrix has {X.shape[1]} columns, "
            f"model expects {expected_features}."
        )

    scores = model.score_samples(X)
    flags = scores < threshold

    output_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        for idx, (meta, score, is_anomaly) in enumerate(
            zip(metadata, scores, flags), start=1
        ):
            record = dict(meta) if isinstance(meta, dict) else {"metadata": meta}
            record.setdefault("line_no", idx)
            record["score"] = float(score)
            record["threshold"] = threshold
            record["is_anomaly"] = bool(is_anomaly)
            record["margin_to_threshold"] = float(score - threshold)
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    anomalies = int(np.count_nonzero(flags))
    events = int(len(scores))

    report = {
        "input": str(input_path),
        "events": events,
        "anomalies": anomalies,
        "anomaly_rate": anomalies / events if events else 0.0,
        "threshold": threshold,
        "score_min": float(np.min(scores)),
        "score_p01": float(np.quantile(scores, 0.01)),
        "score_p02": float(np.quantile(scores, 0.02)),
        "score_p05": float(np.quantile(scores, 0.05)),
        "score_median": float(np.median(scores)),
        "score_mean": float(np.mean(scores)),
        "score_max": float(np.max(scores)),
        "matrix_shape": [int(X.shape[0]), int(X.shape[1])],
        "artifacts": {
            "vectorizer": str(vectorizer_path),
            "model": str(model_path),
            "manifest": str(manifest_path),
            "results": str(output_path),
        },
        "sha256": {
            "input": sha256_file(input_path),
            "vectorizer": sha256_file(vectorizer_path),
            "model": sha256_file(model_path),
            "manifest": sha256_file(manifest_path),
        },
    }

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
        f.write("\n")

    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
