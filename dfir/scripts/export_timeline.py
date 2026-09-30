#!/usr/bin/env python3

import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

INPUT = (
    ROOT
    / "dfir"
    / "timelines"
    / "DFIR-001-timeline.jsonl"
)

CSV_OUT = (
    ROOT
    / "dfir"
    / "timelines"
    / "DFIR-001-timeline.csv"
)

MD_OUT = (
    ROOT
    / "dfir"
    / "timelines"
    / "DFIR-001-timeline.md"
)


COLUMNS = [
    "timestamp",
    "hunt_id",
    "source_type",
    "event_category",
    "rule_id",
    "rule_level",
    "event_id",
    "computer",
    "agent",
    "agent_ip",
    "user",
    "target_user",
    "source_ip",
    "logon_type",
    "image",
    "parent_image",
    "command_line",
    "target_object",
    "details",
    "description",
]


def load_jsonl(path):
    records = []

    if not path.exists():
        raise FileNotFoundError(
            f"Input timeline does not exist: {path}"
        )

    with path.open(
        "r",
        encoding="utf-8"
    ) as f:
        for line_number, line in enumerate(
            f,
            start=1
        ):
            line = line.strip()

            if not line:
                continue

            try:
                obj = json.loads(line)

            except json.JSONDecodeError as exc:
                print(
                    f"[!] Invalid JSON at line "
                    f"{line_number}: {exc}"
                )
                continue

            if isinstance(obj, dict):
                records.append(obj)

    return records


def clean_value(value):
    if value is None:
        return ""

    if isinstance(
        value,
        list
    ):
        return ", ".join(
            str(item)
            for item in value
        )

    if isinstance(
        value,
        dict
    ):
        return json.dumps(
            value,
            ensure_ascii=False
        )

    return str(value)


def write_csv(records):
    CSV_OUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with CSV_OUT.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=COLUMNS,
            extrasaction="ignore"
        )

        writer.writeheader()

        for row in records:
            normalized = {
                column: clean_value(
                    row.get(column)
                )
                for column in COLUMNS
            }

            writer.writerow(
                normalized
            )


def md_escape(value):
    value = clean_value(
        value
    )

    value = value.replace(
        "\n",
        " "
    )

    value = value.replace(
        "\r",
        " "
    )

    value = value.replace(
        "|",
        "\\|"
    )

    return value


def shorten(value, limit=90):
    value = md_escape(
        value
    )

    if len(value) <= limit:
        return value

    return (
        value[:limit - 3]
        + "..."
    )


def analyst_summary(row):
    category = row.get(
        "event_category"
    )

    user = clean_value(
        row.get("user")
    )

    image = clean_value(
        row.get("image")
    )

    parent = clean_value(
        row.get("parent_image")
    )

    source_ip = clean_value(
        row.get("source_ip")
    )

    target = clean_value(
        row.get("target_object")
    )

    description = clean_value(
        row.get("description")
    )

    if category == "authentication_failure":
        return (
            "Failed authentication"
            + (
                f" for {user}"
                if user
                else ""
            )
            + (
                f" from {source_ip}"
                if source_ip
                else ""
            )
        )

    if category == "authentication_success":
        return (
            "Successful authentication"
            + (
                f" for {user}"
                if user
                else ""
            )
            + (
                f" from {source_ip}"
                if source_ip
                else ""
            )
        )

    if category == "powershell_execution":
        return (
            "PowerShell execution"
            + (
                f" by {user}"
                if user
                else ""
            )
        )

    if category == "winrm_remote_execution":
        result = "WinRM child process execution"

        if image:
            result += (
                f": {Path(image).name}"
            )

        if parent:
            result += (
                " <- "
                + Path(parent).name
            )

        if user:
            result += (
                f" as {user}"
            )

        return result

    if category == "registry_persistence":
        result = "Registry Run Key modification"

        if user:
            result += (
                f" by {user}"
            )

        if target:
            result += (
                f": {target}"
            )

        return result

    if category == "detection_alert":
        if description:
            return description

        return "Wazuh detection alert"

    return (
        description
        or category
        or "Event"
    )


def write_markdown(records):
    MD_OUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    lines = []

    lines.append(
        "# DFIR-001 Timeline"
    )

    lines.append("")

    lines.append(
        "Normalized investigation timeline generated "
        "from SOC-LAB threat hunting evidence."
    )

    lines.append("")

    lines.append(
        "> Important: independent controlled validation "
        "events are not treated as one confirmed attack chain."
    )

    lines.append("")

    lines.append(
        f"Total records: **{len(records)}**"
    )

    lines.append("")

    lines.append(
        "## Timeline"
    )

    lines.append("")

    lines.append(
        "| Timestamp | Hunt | Source | Category | "
        "Rule | Event | User | Summary |"
    )

    lines.append(
        "|---|---|---|---|---|---|---|---|"
    )

    for row in records:

        values = [
            shorten(
                row.get("timestamp"),
                35
            ),

            shorten(
                row.get("hunt_id"),
                15
            ),

            shorten(
                row.get("source_type"),
                20
            ),

            shorten(
                row.get("event_category"),
                30
            ),

            shorten(
                row.get("rule_id"),
                12
            )
            or "-",

            shorten(
                row.get("event_id"),
                12
            )
            or "-",

            shorten(
                row.get("user"),
                30
            )
            or "-",

            shorten(
                analyst_summary(row),
                120
            ),
        ]

        lines.append(
            "| "
            + " | ".join(values)
            + " |"
        )

    lines.append("")

    lines.append(
        "## Interpretation Notes"
    )

    lines.append("")

    lines.append(
        "- `raw_telemetry` represents endpoint/security "
        "telemetry evidence."
    )

    lines.append(
        "- `wazuh_alert` represents detection-layer evidence."
    )

    lines.append(
        "- Multiple records with the same timestamp may "
        "represent the same underlying activity observed "
        "at different evidence layers."
    )

    lines.append(
        "- Timeline order alone does not prove causal "
        "relationship between independent lab tests."
    )

    lines.append("")

    lines.append(
        "## Case Status"
    )

    lines.append("")

    lines.append(
        "DFIR-001 remains a controlled investigation case."
    )

    lines.append("")

    lines.append(
        "No real compromise is asserted by this timeline."
    )

    lines.append("")

    MD_OUT.write_text(
        "\n".join(lines),
        encoding="utf-8"
    )


def main():
    print(
        f"[+] Reading: {INPUT}"
    )

    records = load_jsonl(
        INPUT
    )

    print(
        f"[+] Loaded records: "
        f"{len(records)}"
    )

    write_csv(
        records
    )

    print(
        f"[+] CSV: {CSV_OUT}"
    )

    write_markdown(
        records
    )

    print(
        f"[+] Markdown: {MD_OUT}"
    )


if __name__ == "__main__":
    main()
