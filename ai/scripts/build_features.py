#!/usr/bin/env python3

import argparse
import json
import math
import re
from pathlib import Path

import numpy as np
import pandas as pd


SUSPICIOUS_PATTERNS = {
    "encoded_command": re.compile(
        r"(?i)(-enc\b|-encodedcommand\b|frombase64string|base64)"
    ),
    "powershell": re.compile(
        r"(?i)(powershell(?:\.exe)?|pwsh(?:\.exe)?)"
    ),
    "cmd": re.compile(
        r"(?i)(cmd(?:\.exe)?)"
    ),
    "whoami": re.compile(
        r"(?i)\bwhoami\b"
    ),
    "registry_run_key": re.compile(
        r"(?i)software[\\/]+microsoft[\\/]+windows[\\/]+currentversion[\\/]+run"
    ),
    "winrm": re.compile(
        r"(?i)(wsmprovhost|winrm|windows remote management)"
    ),
}


def safe_text(value):
    if value is None:
        return ""
    if isinstance(value, float) and math.isnan(value):
        return ""
    if isinstance(value, list):
        return " ".join(str(x) for x in value)
    return str(value)


def safe_int(value, default=0):
    try:
        if value is None or value == "":
            return default

        text = str(value).strip()

        if text.lower().startswith("0x"):
            return int(text, 16)

        return int(float(text))
    except (TypeError, ValueError):
        return default


def list_len(value):
    if value is None:
        return 0

    if isinstance(value, list):
        return len(value)

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return 0

        # support JSON-like list encoded as string
        if value.startswith("[") and value.endswith("]"):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, list):
                    return len(parsed)
            except Exception:
                pass

        return 1

    return 1


def contains(pattern_name, *values):
    text = " ".join(safe_text(v) for v in values)
    return int(bool(SUSPICIOUS_PATTERNS[pattern_name].search(text)))


def build_feature_row(record):
    timestamp = pd.to_datetime(
        record.get("timestamp"),
        errors="coerce",
        utc=True,
    )

    command_line = safe_text(record.get("command_line"))
    parent_command_line = safe_text(record.get("parent_command_line"))
    description = safe_text(record.get("description"))
    details = safe_text(record.get("details"))
    image = safe_text(record.get("image"))
    parent_image = safe_text(record.get("parent_image"))
    target_object = safe_text(record.get("target_object"))

    combined_process_text = " ".join(
        [
            command_line,
            parent_command_line,
            description,
            details,
            image,
            parent_image,
        ]
    )

    event_category = safe_text(record.get("event_category")).lower()
    source_type = safe_text(record.get("source_type")).lower()

    source_ip = safe_text(record.get("source_ip"))
    destination_ip = safe_text(record.get("destination_ip"))

    rule_level = safe_int(record.get("rule_level"))
    event_id = safe_int(record.get("event_id"))
    logon_type = safe_int(record.get("logon_type"))

    row = {
        # identifiers retained for investigation
        "timestamp": record.get("timestamp"),
        "hunt_id": safe_text(record.get("hunt_id")),
        "source_file": safe_text(record.get("source_file")),
        "event_category": safe_text(record.get("event_category")),
        "rule_id": safe_text(record.get("rule_id")),
        "event_id_raw": safe_text(record.get("event_id")),
        "agent": safe_text(record.get("agent")),
        "computer": safe_text(record.get("computer")),
        "user": safe_text(record.get("user")),

        # numerical / model features
        "rule_level": rule_level,
        "event_id_numeric": event_id,
        "logon_type_numeric": logon_type,

        "hour": timestamp.hour if not pd.isna(timestamp) else -1,
        "day_of_week": timestamp.dayofweek if not pd.isna(timestamp) else -1,

        "is_wazuh_alert": int(source_type == "wazuh_alert"),
        "is_raw_telemetry": int(source_type == "raw_telemetry"),

        "is_auth_success": int(
            event_category == "authentication_success"
        ),
        "is_auth_failure": int(
            event_category == "authentication_failure"
        ),
        "is_powershell_execution": int(
            event_category == "powershell_execution"
        ),
        "is_winrm_execution": int(
            event_category == "winrm_remote_execution"
        ),
        "is_registry_persistence": int(
            event_category == "registry_persistence"
        ),
        "is_detection_alert": int(
            event_category == "detection_alert"
        ),

        "has_encoded_command": contains(
            "encoded_command",
            command_line,
            description,
        ),
        "has_powershell": contains(
            "powershell",
            combined_process_text,
        ),
        "has_cmd": contains(
            "cmd",
            combined_process_text,
        ),
        "has_whoami": contains(
            "whoami",
            combined_process_text,
        ),
        "has_registry_run_key": contains(
            "registry_run_key",
            target_object,
            description,
        ),
        "has_winrm": contains(
            "winrm",
            parent_image,
            description,
            parent_command_line,
        ),

        "has_source_ip": int(bool(source_ip)),
        "has_destination_ip": int(bool(destination_ip)),

        "has_user": int(bool(safe_text(record.get("user")))),
        "has_target_user": int(bool(safe_text(record.get("target_user")))),

        "has_command_line": int(bool(command_line)),
        "has_parent_process": int(bool(parent_image)),
        "has_registry_target": int(bool(target_object)),
        "has_status": int(bool(safe_text(record.get("status")))),

        "mitre_id_count": list_len(record.get("mitre_ids")),
        "mitre_tactic_count": list_len(record.get("mitre_tactics")),
        "mitre_technique_count": list_len(record.get("mitre_techniques")),

        "command_line_length": len(command_line),
        "description_length": len(description),
        "details_length": len(details),

        "process_id_numeric": safe_int(record.get("process_id")),
        "parent_process_id_numeric": safe_int(
            record.get("parent_process_id")
        ),
        "source_port_numeric": safe_int(record.get("source_port")),
        "destination_port_numeric": safe_int(
            record.get("destination_port")
        ),
    }

    return row


def main():
    parser = argparse.ArgumentParser(
        description="Build ML feature dataset from SOC-LAB DFIR JSONL timeline."
    )

    parser.add_argument(
        "--input",
        default="dfir/timelines/DFIR-001-timeline.jsonl",
        help="Input JSONL timeline",
    )

    parser.add_argument(
        "--output",
        default="ai/features/DFIR-001-features.csv",
        help="Output feature CSV",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        raise SystemExit(
            f"[!] Timeline not found: {input_path}"
        )

    rows = []

    with input_path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    f"[!] Invalid JSON at line {line_number}: {exc}"
                )

            rows.append(build_feature_row(record))

    if not rows:
        raise SystemExit("[!] Timeline contains no records.")

    df = pd.DataFrame(rows)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    df.to_csv(
        output_path,
        index=False,
    )

    feature_columns = [
        col
        for col in df.columns
        if col not in {
            "timestamp",
            "hunt_id",
            "source_file",
            "event_category",
            "rule_id",
            "event_id_raw",
            "agent",
            "computer",
            "user",
        }
    ]

    print("[+] Feature engineering complete")
    print(f"[+] Input : {input_path}")
    print(f"[+] Output: {output_path}")
    print(f"[+] Rows  : {len(df)}")
    print(f"[+] ML features: {len(feature_columns)}")

    print("\n[+] Event categories:")
    print(
        df["event_category"]
        .value_counts(dropna=False)
        .to_string()
    )

    print("\n[+] Feature columns:")
    for feature in feature_columns:
        print(f"    - {feature}")


if __name__ == "__main__":
    main()
