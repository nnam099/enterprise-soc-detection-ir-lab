#!/usr/bin/env python3
import argparse
import json
import math
from pathlib import Path

import joblib
import numpy as np
from scipy import sparse
from sklearn.feature_extraction import DictVectorizer


BASE_NUMERIC_FIELDS = [
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
    "parent_is_office",
    "parent_is_browser",
    "parent_is_service",
    "is_external_ip",
    "path_depth",
]

DERIVED_NUMERIC_FIELDS = [
    "powershell_encoded",
    "powershell_plain_command",
    "is_browser",
    "browser_gpu_process",
    "browser_renderer",
    "browser_utility",
    "base64_like_non_browser",
    "parent_same_image",
    "parent_is_wazuh_agent",
    "command_length_log",
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
    "command_length_bucket",
]


def _as_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _command_length_bucket(length):
    if length <= 0:
        return "none"
    if length <= 80:
        return "short"
    if length <= 200:
        return "medium"
    if length <= 500:
        return "long"
    return "very_long"


def _derive_features(obj):
    image_name = str(obj.get("image_name", "") or "").strip().lower()
    parent_image_name = str(obj.get("parent_image_name", "") or "").strip().lower()
    command_line = str(obj.get("command_line", "") or "")

    is_powershell = int(_as_float(obj.get("is_powershell", 0)) > 0)
    has_encoded_command = int(_as_float(obj.get("has_encoded_command", 0)) > 0)
    has_base64_like_string = int(_as_float(obj.get("has_base64_like_string", 0)) > 0)

    browser_names = {
        "msedge.exe",
        "msedgewebview2.exe",
        "chrome.exe",
        "firefox.exe",
        "brave.exe",
    }
    is_browser = int(image_name in browser_names)

    cmd_lower = command_line.lower()
    browser_gpu_process = int(is_browser and "--type=gpu-process" in cmd_lower)
    browser_renderer = int(is_browser and "--type=renderer" in cmd_lower)
    browser_utility = int(is_browser and "--type=utility" in cmd_lower)

    powershell_encoded = int(is_powershell and has_encoded_command)
    powershell_plain_command = int(is_powershell and not has_encoded_command and bool(command_line.strip()))
    base64_like_non_browser = int(has_base64_like_string and not is_browser)

    parent_same_image = int(bool(image_name) and image_name == parent_image_name)
    parent_is_wazuh_agent = int(parent_image_name == "wazuh-agent.exe")

    command_length = max(0.0, _as_float(obj.get("command_length", len(command_line))))
    command_length_log = math.log1p(command_length)
    command_length_bucket = _command_length_bucket(command_length)

    return {
        "powershell_encoded": powershell_encoded,
        "powershell_plain_command": powershell_plain_command,
        "is_browser": is_browser,
        "browser_gpu_process": browser_gpu_process,
        "browser_renderer": browser_renderer,
        "browser_utility": browser_utility,
        "base64_like_non_browser": base64_like_non_browser,
        "parent_same_image": parent_same_image,
        "parent_is_wazuh_agent": parent_is_wazuh_agent,
        "command_length_log": command_length_log,
        "command_length_bucket": command_length_bucket,
    }


def load_rows(path):
    rows = []
    metadata = []

    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            obj = json.loads(line)
            derived = _derive_features(obj)
            feat = {}

            for field in BASE_NUMERIC_FIELDS:
                feat[field] = _as_float(obj.get(field, 0))

            for field in DERIVED_NUMERIC_FIELDS:
                feat[field] = float(derived[field])

            for field in CATEGORICAL_FIELDS:
                if field == "command_length_bucket":
                    value = derived[field]
                else:
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
                "parent_image_name": obj.get("parent_image_name", ""),
                "command_line": obj.get("command_line", ""),
                "target_filename": obj.get("target_filename", ""),
                "registry_target_object": obj.get("registry_target_object", ""),
                "dns_query_name": obj.get("dns_query_name", ""),
                "powershell_encoded": derived["powershell_encoded"],
                "powershell_plain_command": derived["powershell_plain_command"],
                "is_browser": derived["is_browser"],
                "browser_gpu_process": derived["browser_gpu_process"],
                "browser_renderer": derived["browser_renderer"],
                "browser_utility": derived["browser_utility"],
                "base64_like_non_browser": derived["base64_like_non_browser"],
                "parent_same_image": derived["parent_same_image"],
                "parent_is_wazuh_agent": derived["parent_is_wazuh_agent"],
                "command_length_log": derived["command_length_log"],
                "command_length_bucket": derived["command_length_bucket"],
            })

    return rows, metadata


def main():
    parser = argparse.ArgumentParser(
        description="Build SOC-LAB feature matrix v3 from normalized Windows JSONL."
    )
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

    sparse.save_npz(output_dir / "X_baseline_v3.npz", X)
    joblib.dump(vectorizer, output_dir / "dict_vectorizer_v3.joblib")

    feature_names = vectorizer.get_feature_names_out().tolist()

    with open(output_dir / "feature_names_v3.json", "w", encoding="utf-8") as f:
        json.dump(feature_names, f, indent=2, ensure_ascii=False)

    with open(output_dir / "metadata_v3.jsonl", "w", encoding="utf-8") as f:
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
        "base_numeric_fields": BASE_NUMERIC_FIELDS,
        "derived_numeric_fields": DERIVED_NUMERIC_FIELDS,
        "categorical_fields": CATEGORICAL_FIELDS,
        "artifacts": {
            "matrix": "X_baseline_v3.npz",
            "vectorizer": "dict_vectorizer_v3.joblib",
            "feature_names": "feature_names_v3.json",
            "metadata": "metadata_v3.jsonl",
        },
    }

    with open(output_dir / "feature_matrix_v3_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
