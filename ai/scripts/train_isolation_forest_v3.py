#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
from scipy import sparse
from sklearn.ensemble import IsolationForest

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    parser = argparse.ArgumentParser(description="Train SOC-LAB Isolation Forest v3 on benign baseline.")
    parser.add_argument("matrix")
    parser.add_argument("output_dir")
    parser.add_argument("--contamination", type=float, default=0.02)
    parser.add_argument("--estimators", type=int, default=300)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--threshold-quantile", type=float, default=0.02)
    args = parser.parse_args()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    X = sparse.load_npz(args.matrix)

    model = IsolationForest(
        n_estimators=args.estimators,
        contamination=args.contamination,
        random_state=args.seed,
        n_jobs=-1,
    )
    model.fit(X)

    # sklearn: larger score = more normal. Lower = more anomalous.
    scores = model.score_samples(X)
    threshold = float(np.quantile(scores, args.threshold_quantile))
    flags = scores < threshold

    model_path = out / "isolation_forest_v3.joblib"
    scores_path = out / "baseline_scores_v3.npy"
    manifest_path = out / "training_manifest_v3.json"

    joblib.dump(model, model_path)
    np.save(scores_path, scores)

    report = {
        "rows": int(X.shape[0]),
        "features": int(X.shape[1]),
        "n_estimators": args.estimators,
        "contamination": args.contamination,
        "random_state": args.seed,
        "threshold_quantile": args.threshold_quantile,
        "threshold": threshold,
        "baseline_score_min": float(scores.min()),
        "baseline_score_p01": float(np.quantile(scores, 0.01)),
        "baseline_score_p02": float(np.quantile(scores, 0.02)),
        "baseline_score_p05": float(np.quantile(scores, 0.05)),
        "baseline_score_median": float(np.median(scores)),
        "baseline_score_mean": float(scores.mean()),
        "baseline_score_max": float(scores.max()),
        "baseline_flagged_below_threshold": int(flags.sum()),
        "baseline_flag_rate": float(flags.mean()),
        "matrix_sha256": sha256_file(args.matrix),
        "model_sha256": sha256_file(model_path),
        "scores_sha256": sha256_file(scores_path),
        "artifacts": {
            "model": model_path.name,
            "scores": scores_path.name,
            "manifest": manifest_path.name,
        },
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
