#!/usr/bin/env python3

from pathlib import Path

import pandas as pd


INPUT = Path(
    "ai/results/DFIR-001-anomaly-scores.csv"
)

OUTPUT = Path(
    "ai/results/DFIR-001-anomaly-report.md"
)


def main():
    if not INPUT.exists():
        raise SystemExit(
            f"[!] Missing input: {INPUT}"
        )

    df = pd.read_csv(INPUT)

    anomalies = df[
        df["is_anomaly"] == 1
    ].copy()

    lines = []

    lines.append(
        "# DFIR-001 AI-Assisted Anomaly Analysis"
    )
    lines.append("")
    lines.append(
        "## 1. Purpose"
    )
    lines.append("")
    lines.append(
        "This report documents the Phase 6B "
        "AI-assisted anomaly detection experiment "
        "for the SOC-LAB project."
    )
    lines.append("")
    lines.append(
        "The Isolation Forest model is used as an "
        "analyst-triage aid and not as a malicious/"
        "benign classifier."
    )
    lines.append("")

    lines.append(
        "## 2. Dataset Summary"
    )
    lines.append("")
    lines.append(
        f"- Total events: {len(df)}"
    )
    lines.append(
        f"- Events marked anomalous: "
        f"{int(df['is_anomaly'].sum())}"
    )
    lines.append(
        "- Source: normalized DFIR-001 timeline"
    )
    lines.append(
        "- Model: Isolation Forest"
    )
    lines.append(
        "- Contamination: 0.20"
    )
    lines.append(
        "- Random seed: 42"
    )
    lines.append("")

    lines.append(
        "## 3. Ranked Events"
    )
    lines.append("")
    lines.append(
        "| Rank | Hunt | Category | Rule | "
        "Level | Score | Anomaly | Priority |"
    )
    lines.append(
        "|---:|---|---|---:|---:|---:|---|---|"
    )

    for _, row in df.iterrows():
        lines.append(
            f"| {int(row['anomaly_rank'])} "
            f"| {row['hunt_id']} "
            f"| {row['event_category']} "
            f"| {row['rule_id']} "
            f"| {row['rule_level']} "
            f"| {row['anomaly_score']:.6f} "
            f"| {'YES' if row['is_anomaly'] == 1 else 'NO'} "
            f"| {row['analyst_priority']} |"
        )

    lines.append("")

    lines.append(
        "## 4. Model-Flagged Anomalies"
    )
    lines.append("")

    for _, row in anomalies.iterrows():
        lines.append(
            f"### Rank {int(row['anomaly_rank'])} "
            f"— {row['hunt_id']} / "
            f"{row['event_category']}"
        )
        lines.append("")
        lines.append(
            f"- Rule ID: {row['rule_id']}"
        )
        lines.append(
            f"- Rule level: {row['rule_level']}"
        )
        lines.append(
            f"- Anomaly score: "
            f"{row['anomaly_score']:.6f}"
        )
        lines.append(
            f"- Analyst priority: "
            f"{row['analyst_priority']}"
        )
        lines.append("")

    lines.append(
        "## 5. Analyst Interpretation"
    )
    lines.append("")
    lines.append(
        "The highest-ranked anomaly was an "
        "authentication-success event. This does "
        "not indicate that the event was malicious."
    )
    lines.append("")
    lines.append(
        "Isolation Forest identifies statistical "
        "rarity relative to the training data. "
        "Because the current dataset contains only "
        "a small number of controlled threat-hunting "
        "events, ordinary activity can appear more "
        "statistically unusual than known suspicious "
        "activity."
    )
    lines.append("")
    lines.append(
        "For example, encoded PowerShell, failed "
        "authentication attempts, WinRM execution, "
        "and registry persistence are represented "
        "multiple times in the dataset. Their "
        "presence in the training baseline reduces "
        "their statistical novelty."
    )
    lines.append("")

    lines.append(
        "## 6. Key Finding"
    )
    lines.append("")
    lines.append(
        "**Anomaly does not mean malicious.**"
    )
    lines.append("")
    lines.append(
        "The anomaly score must be correlated with "
        "security context such as rule severity, "
        "MITRE ATT&CK mappings, process ancestry, "
        "authentication activity, command-line "
        "content, and other telemetry."
    )
    lines.append("")

    lines.append(
        "## 7. Limitations"
    )
    lines.append("")
    lines.append(
        "- Only 10 events are currently available."
    )
    lines.append(
        "- The dataset contains controlled "
        "threat-hunting activity."
    )
    lines.append(
        "- No representative benign baseline has "
        "yet been collected."
    )
    lines.append(
        "- The current model must not be interpreted "
        "as a production malware classifier."
    )
    lines.append(
        "- Precision, recall, F1-score, and accuracy "
        "are not meaningful at this stage."
    )
    lines.append("")

    lines.append(
        "## 8. Next Step"
    )
    lines.append("")
    lines.append(
        "Phase 6C will collect a larger benign "
        "Windows telemetry baseline and separate "
        "controlled suspicious activity from normal "
        "activity before evaluating anomaly-detection "
        "quality."
    )
    lines.append("")

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print(
        f"[+] Report written: {OUTPUT}"
    )


if __name__ == "__main__":
    main()
