#!/usr/bin/env python3

import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter


ROOT = Path(__file__).resolve().parents[2]

HUNTING = ROOT / "hunting" / "evidence"

OUT = (
    ROOT
    / "dfir"
    / "timelines"
    / "DFIR-001-timeline.jsonl"
)


def safe_get(obj, *path):
    cur = obj

    for key in path:
        if not isinstance(cur, dict):
            return None

        cur = cur.get(key)

    return cur


def load_json_file(path):
    try:
        text = path.read_text(
            encoding="utf-8"
        ).strip()

    except UnicodeDecodeError:
        text = path.read_text(
            encoding="utf-8",
            errors="replace"
        ).strip()

    if not text:
        return []

    try:
        obj = json.loads(text)

        if isinstance(obj, dict):
            return [obj]

        if isinstance(obj, list):
            return [
                item
                for item in obj
                if isinstance(item, dict)
            ]

        return []

    except json.JSONDecodeError:
        pass

    records = []

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        try:
            obj = json.loads(line)

        except json.JSONDecodeError:
            continue

        if isinstance(obj, dict):
            records.append(obj)

    return records


def infer_source_type(source_file, record):
    name = source_file.name.lower()

    if "rule-" in name:
        return "wazuh_alert"

    if "sysmon" in name:
        return "raw_telemetry"

    if "success-4624" in name:
        return "raw_telemetry"

    if "event-" in name:
        return "raw_telemetry"

    rule_id = safe_get(
        record,
        "rule",
        "id"
    )

    if rule_id:
        return "wazuh_alert"

    return "raw_telemetry"


def normalize_windows_path(value):
    """
    Normalize Windows strings exported through JSON/Wazuh.

    Example:

        HKU\\\\SID\\\\SOFTWARE\\\\Microsoft...

    becomes:

        hku\\sid\\software\\microsoft...
    """

    if not value:
        return ""

    value = str(value).lower()

    while "\\\\" in value:
        value = value.replace(
            "\\\\",
            "\\"
        )

    return value


def classify_event(
    event_id,
    rule_id,
    image,
    parent_image,
    target_object,
):
    event_id = str(
        event_id or ""
    )

    image_lower = normalize_windows_path(
        image
    )

    parent_lower = normalize_windows_path(
        parent_image
    )

    target_lower = normalize_windows_path(
        target_object
    )

    # Authentication
    if event_id == "4624":
        return "authentication_success"

    if event_id == "4625":
        return "authentication_failure"

    # Registry
    if event_id == "13":

        if (
            "\\currentversion\\run"
            in target_lower
        ):
            return "registry_persistence"

        return "registry_modification"

    # Process creation
    if event_id == "1":

        if (
            "wsmprovhost.exe"
            in parent_lower
        ):
            return "winrm_remote_execution"

        if (
            "powershell.exe"
            in image_lower
        ):
            return "powershell_execution"

        if (
            "cmd.exe"
            in image_lower
        ):
            return "command_execution"

        return "process_creation"

    if rule_id:
        return "detection_alert"

    return "other"


def parse_timestamp(value):
    if not value:
        return datetime.max.replace(
            tzinfo=timezone.utc
        )

    try:
        parsed = datetime.fromisoformat(
            str(value).replace(
                "Z",
                "+00:00"
            )
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed

    except (
        ValueError,
        TypeError
    ):
        return datetime.max.replace(
            tzinfo=timezone.utc
        )


def normalize(
    record,
    source_file,
    hunt_id,
):
    if not isinstance(
        record,
        dict
    ):
        return None

    rule_id = safe_get(
        record,
        "rule",
        "id"
    )

    rule_level = safe_get(
        record,
        "rule",
        "level"
    )

    description = safe_get(
        record,
        "rule",
        "description"
    )

    mitre_ids = safe_get(
        record,
        "rule",
        "mitre",
        "id"
    )

    mitre_tactics = safe_get(
        record,
        "rule",
        "mitre",
        "tactic"
    )

    mitre_techniques = safe_get(
        record,
        "rule",
        "mitre",
        "technique"
    )

    event_id = safe_get(
        record,
        "data",
        "win",
        "system",
        "eventID"
    )

    computer = safe_get(
        record,
        "data",
        "win",
        "system",
        "computer"
    )

    event_data = safe_get(
        record,
        "data",
        "win",
        "eventdata"
    )

    if not isinstance(
        event_data,
        dict
    ):
        event_data = {}

    timestamp = record.get(
        "timestamp"
    )

    image = event_data.get(
        "image"
    )

    parent_image = event_data.get(
        "parentImage"
    )

    target_object = event_data.get(
        "targetObject"
    )

    source_type = infer_source_type(
        source_file,
        record
    )

    event_category = classify_event(
        event_id=event_id,
        rule_id=rule_id,
        image=image,
        parent_image=parent_image,
        target_object=target_object,
    )

    user = (
        event_data.get("user")
        or event_data.get("targetUserName")
        or event_data.get("subjectUserName")
    )

    return {
        "timestamp": timestamp,

        "hunt_id": hunt_id,

        "source_file": str(
            source_file.relative_to(
                ROOT
            )
        ),

        "source_type": source_type,

        "event_category": event_category,

        # Wazuh rule
        "rule_id": rule_id,
        "rule_level": rule_level,
        "description": description,

        # MITRE
        "mitre_ids": mitre_ids,
        "mitre_tactics": mitre_tactics,
        "mitre_techniques": mitre_techniques,

        # Windows event
        "event_id": event_id,
        "computer": computer,

        # Agent
        "agent": safe_get(
            record,
            "agent",
            "name"
        ),

        "agent_ip": safe_get(
            record,
            "agent",
            "ip"
        ),

        # Identity
        "user": user,

        "target_user": event_data.get(
            "targetUserName"
        ),

        "target_domain": event_data.get(
            "targetDomainName"
        ),

        "subject_user": event_data.get(
            "subjectUserName"
        ),

        # Process
        "image": image,

        "original_file_name": event_data.get(
            "originalFileName"
        ),

        "command_line": event_data.get(
            "commandLine"
        ),

        "parent_image": parent_image,

        "parent_command_line": event_data.get(
            "parentCommandLine"
        ),

        "process_id": (
            event_data.get("processId")
            or event_data.get("processID")
        ),

        "parent_process_id": (
            event_data.get("parentProcessId")
            or event_data.get("parentProcessID")
        ),

        # Registry
        "target_object": target_object,

        "details": event_data.get(
            "details"
        ),

        # Network/auth
        "source_ip": (
            event_data.get("ipAddress")
            or event_data.get("sourceIp")
            or event_data.get("sourceIP")
        ),

        "source_port": (
            event_data.get("ipPort")
            or event_data.get("sourcePort")
        ),

        "destination_ip": event_data.get(
            "destinationIp"
        ),

        "destination_port": event_data.get(
            "destinationPort"
        ),

        "logon_type": event_data.get(
            "logonType"
        ),

        "authentication_package": event_data.get(
            "authenticationPackageName"
        ),

        "status": event_data.get(
            "status"
        ),

        "substatus": event_data.get(
            "subStatus"
        ),

        "failure_reason": event_data.get(
            "failureReason"
        ),
    }


def collect_records():
    collected = []

    if not HUNTING.exists():
        print(
            f"[!] Missing evidence directory: "
            f"{HUNTING}"
        )

        return collected

    for hunt_dir in sorted(
        HUNTING.glob("HUNT-*")
    ):
        if not hunt_dir.is_dir():
            continue

        hunt_id = hunt_dir.name

        for path in sorted(
            hunt_dir.glob("*.json")
        ):

            records = load_json_file(
                path
            )

            if not records:
                print(
                    "[!] No usable JSON records: "
                    f"{path.relative_to(ROOT)}"
                )

                continue

            for record in records:

                row = normalize(
                    record,
                    path,
                    hunt_id
                )

                if row is not None:
                    collected.append(
                        row
                    )

    return collected


def write_timeline(records):
    OUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUT.open(
        "w",
        encoding="utf-8"
    ) as f:

        for row in records:

            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False
                )
                + "\n"
            )


def print_counter(
    title,
    values
):
    print(
        f"[+] {title}:"
    )

    counter = Counter(
        values
    )

    for name, count in sorted(
        counter.items()
    ):
        print(
            f"    {name}: {count}"
        )


def main():
    print(
        f"[+] Repository root: "
        f"{ROOT}"
    )

    print(
        f"[+] Evidence root: "
        f"{HUNTING}"
    )

    records = collect_records()

    records.sort(
        key=lambda row: parse_timestamp(
            row.get(
                "timestamp"
            )
        )
    )

    write_timeline(
        records
    )

    print(
        f"[+] Timeline records: "
        f"{len(records)}"
    )

    print(
        f"[+] Output: "
        f"{OUT}"
    )

    print_counter(
        "Records by hunt",
        [
            row.get(
                "hunt_id",
                "UNKNOWN"
            )
            for row in records
        ]
    )

    print_counter(
        "Records by source type",
        [
            row.get(
                "source_type",
                "UNKNOWN"
            )
            for row in records
        ]
    )

    print_counter(
        "Records by event category",
        [
            row.get(
                "event_category",
                "UNKNOWN"
            )
            for row in records
        ]
    )


if __name__ == "__main__":
    main()
