#!/usr/bin/env python3

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
import sklearn

from sklearn.ensemble import IsolationForest


MODEL_FEATURES = [
    "rule_level",
    "hour",
    "day_of_week",

    "is_wazuh_alert",
    "is_raw_telemetry",

    "is_auth_success",
    "is_auth_failure",
    "is_powershell_execution",
    "is_winrm_execution",
    "is_registry_persistence",
    "is_detection_alert",

    "has_encoded_command",
    "has_powershell",
    "has_cmd",
    "has_whoami",
    "has_registry_run_key",
    "has_winrm",

    "has_source_ip",
    "has_destination_ip",
    "has_user",
    "has_target_user",
    "has_command_line",
    "has_parent_process",
    "has_registry_target",
    "has_status",

    "mitre_id_count",
    "mitre_tactic_count",
    "mitre_technique_count",

    "command_line_length",
    "description_length",
    "details_length",
]


def main():
    parser = argparse.ArgumentParser(
        description="Train SOC-LAB Isolation Forest anomaly detector."
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
        "--metadata",
        default="ai/models/isolation_forest.metadata.json",
    )

    parser.add_argument(
        "--contamination",
        type=float,
        default=0.20,
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42,
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    model_path = Path(args.model)
    metadata_path = Path(args.metadata)

    if not input_path.exists():
        raise SystemExit(
            f"[!] Feature dataset not found: {input_path}"
        )

    df = pd.read_csv(input_path)

    missing = [
        feature
        for feature in MODEL_FEATURES
        if feature not in df.columns
    ]

    if missing:
        raise SystemExit(
            "[!] Missing features: "
            + ", ".join(missing)
        )

    X = (
        df[MODEL_FEATURES]
        .apply(pd.to_numeric, errors="coerce")
        .fillna(0)
    )

    if len(X) < 5:
        raise SystemExit(
            "[!] Too few samples to train even a demonstration model."
        )

    model = IsolationForest(
        n_estimators=200,
        contamination=args.contamination,
        random_state=args.seed,
        n_jobs=-1,
    )

    model.fit(X)

    model_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    package = {
        "model": model,
        "features": MODEL_FEATURES,
    }

    joblib.dump(
        package,
        model_path,
    )

    metadata = {
        "model_type": "IsolationForest",
        "purpose": "SOC anomaly triage demonstration",
        "training_dataset": str(input_path),
        "training_samples": int(len(X)),
        "feature_count": len(MODEL_FEATURES),
        "features": MODEL_FEATURES,
        "n_estimators": 200,
        "contamination": args.contamination,
        "random_state": args.seed,
        "sklearn_version": sklearn.__version__,
        "trained_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "limitations": [
            "Small controlled dataset",
            "Training data contains threat-hunting activity",
            "Not a production malicious/benign classifier",
            "Anomaly output requires analyst validation",
        ],
    }

    metadata_path.write_text(
        json.dumps(
            metadata,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print("[+] Isolation Forest training complete")
    print(f"[+] Samples       : {len(X)}")
    print(f"[+] Features      : {len(MODEL_FEATURES)}")
    print(f"[+] Estimators    : 200")
    print(f"[+] Contamination : {args.contamination}")
    print(f"[+] Random seed   : {args.seed}")
    print(f"[+] Model         : {model_path}")
    print(f"[+] Metadata      : {metadata_path}")


if __name__ == "__main__":
    main()
