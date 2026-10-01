# DFIR-001 AI-Assisted Anomaly Analysis

## 1. Purpose

This report documents the Phase 6B AI-assisted anomaly detection experiment for the SOC-LAB project.

The Isolation Forest model is used as an analyst-triage aid and not as a malicious/benign classifier.

## 2. Dataset Summary

- Total events: 10
- Events marked anomalous: 2
- Source: normalized DFIR-001 timeline
- Model: Isolation Forest
- Contamination: 0.20
- Random seed: 42

## 3. Ranked Events

| Rank | Hunt | Category | Rule | Level | Score | Anomaly | Priority |
|---:|---|---|---:|---:|---:|---|---|
| 1 | HUNT-002 | authentication_success | 67022 | 3 | 0.043444 | YES | MEDIUM |
| 2 | HUNT-004 | registry_persistence | 100501 | 7 | 0.013553 | YES | MEDIUM |
| 3 | HUNT-004 | registry_persistence | 100501 | 7 | -0.003388 | NO | NORMAL |
| 4 | HUNT-001 | detection_alert | 100504 | 8 | -0.010139 | NO | NORMAL |
| 5 | HUNT-003 | winrm_remote_execution | 100502 | 8 | -0.030492 | NO | NORMAL |
| 6 | HUNT-001 | powershell_execution | 92057 | 12 | -0.036527 | NO | NORMAL |
| 7 | HUNT-002 | authentication_failure | 100503 | 10 | -0.043127 | NO | NORMAL |
| 8 | HUNT-002 | authentication_failure | 60122 | 5 | -0.051453 | NO | NORMAL |
| 9 | HUNT-003 | winrm_remote_execution | 100502 | 8 | -0.054536 | NO | NORMAL |
| 10 | HUNT-001 | powershell_execution | 92027 | 4 | -0.061772 | NO | NORMAL |

## 4. Model-Flagged Anomalies

### Rank 1 — HUNT-002 / authentication_success

- Rule ID: 67022
- Rule level: 3
- Anomaly score: 0.043444
- Analyst priority: MEDIUM

### Rank 2 — HUNT-004 / registry_persistence

- Rule ID: 100501
- Rule level: 7
- Anomaly score: 0.013553
- Analyst priority: MEDIUM

## 5. Analyst Interpretation

The highest-ranked anomaly was an authentication-success event. This does not indicate that the event was malicious.

Isolation Forest identifies statistical rarity relative to the training data. Because the current dataset contains only a small number of controlled threat-hunting events, ordinary activity can appear more statistically unusual than known suspicious activity.

For example, encoded PowerShell, failed authentication attempts, WinRM execution, and registry persistence are represented multiple times in the dataset. Their presence in the training baseline reduces their statistical novelty.

## 6. Key Finding

**Anomaly does not mean malicious.**

The anomaly score must be correlated with security context such as rule severity, MITRE ATT&CK mappings, process ancestry, authentication activity, command-line content, and other telemetry.

## 7. Limitations

- Only 10 events are currently available.
- The dataset contains controlled threat-hunting activity.
- No representative benign baseline has yet been collected.
- The current model must not be interpreted as a production malware classifier.
- Precision, recall, F1-score, and accuracy are not meaningful at this stage.

## 8. Next Step

Phase 6C will collect a larger benign Windows telemetry baseline and separate controlled suspicious activity from normal activity before evaluating anomaly-detection quality.

