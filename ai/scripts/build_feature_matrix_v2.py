#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

import joblib
import numpy as np
from scipy import sparse
from sklearn.feature_extraction import DictVectorizer

NUMERIC_FIELDS = [
    "hour",
    "day_of_week",
    "is_powershell",
    "is_cmd",
    "is_lolbin",
    "is_system32",
    "is_user_writable_path",
    "has_encoded_command",
    "has_url",
    "has_ip_address",
    "has_base64_like_string",
    "parent_is_office",
    "parent_is_browser",
    "parent_is_service",
    "is_external_ip",
    "command_length",
    "path_depth",
]

CATEGORICAL_FIELDS = [
    "event_id",
    "channel",
    "provider",
    "image_name",
    "parent_image_name",
    "integrity_level",
    "protocol",
    "destination_port_category",
]

def load_rows(path):
    rows = []
    metadata = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)

            feat = {}
            for field in NUMERIC_FIELDS:
                value = obj.get(field, 0)
                try:
                    feat[field] = float(value)
                except (TypeError, ValueError):
                    feat[field] = 0.0

            for field in CATEGORICAL_FIELDS:
                value = str(obj.get(field, "") or "").strip()
                if value:
                    feat[field] = value

            rows.append(feat)
            metadata.append({
                "line_no": line_no,
                "timestamp": obj.get("timestamp", ""),
                "event_id": obj.get("event_id", ""),
                "channel": obj.get("channel", ""),
                "image_name": obj.get("image_name", ""),
                "command_line": obj.get("command_line", ""),
                "target_filename": obj.get("target_filename", ""),
                "registry_target_object": obj.get("registry_target_object", ""),
                "dns_query_name": obj.get("dns_query_name", ""),
            })
    return rows, metadata

def main():
    parser = argparse.ArgumentParser(description="Build SOC-LAB feature matrix v2 from normalized Windows JSONL.")
    parser.add_argument("input")
    parser.add_argument("output_dir")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    rows, metadata = load_rows(args.input)
    if not rows:
        raise SystemExit("No usable events found.")

    vectorizer = DictVectorizer(sparse=True, sort=True)
    X = vectorizer.fit_transform(rows).astype(np.float64)

    sparse.save_npz(output_dir / "X_baseline_v2.npz", X)
    joblib.dump(vectorizer, output_dir / "dict_vectorizer_v2.joblib")

    feature_names = vectorizer.get_feature_names_out().tolist()
    with open(output_dir / "feature_names_v2.json", "w", encoding="utf-8") as f:
        json.dump(feature_names, f, indent=2, ensure_ascii=False)

    with open(output_dir / "metadata_v2.jsonl", "w", encoding="utf-8") as f:
        for row in metadata:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")

    nonzero_per_row = np.diff(X.indptr)
    report = {
        "rows": int(X.shape[0]),
        "features": int(X.shape[1]),
        "nnz": int(X.nnz),
        "avg_nonzero_features_per_row": float(nonzero_per_row.mean()),
        "min_nonzero_features_per_row": int(nonzero_per_row.min()),
        "max_nonzero_features_per_row": int(nonzero_per_row.max()),
        "numeric_fields": NUMERIC_FIELDS,
        "categorical_fields": CATEGORICAL_FIELDS,
        "artifacts": {
            "matrix": "X_baseline_v2.npz",
            "vectorizer": "dict_vectorizer_v2.joblib",
            "feature_names": "feature_names_v2.json",
            "metadata": "metadata_v2.jsonl"
        }
    }

    with open(output_dir / "feature_matrix_v2_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
