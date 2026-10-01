# AI-Assisted SOC Analytics

Experimental AI-assisted anomaly detection pipeline for the Enterprise SOC Detection & Incident Response Lab.

## Architecture

```text
Windows / Sysmon
      |
      v
    Wazuh
      |
      v
Threat Hunting
      |
      v
DFIR Normalized Timeline
      |
      v
Feature Engineering
      |
      v
Isolation Forest
      |
      v
Anomaly Ranking
      |
      v
SOC Analyst Investigation
```

## Pipeline

### 1. Feature Engineering

Script:

```text
ai/scripts/build_features.py
```

Input:

```text
dfir/timelines/DFIR-001-timeline.jsonl
```

Output:

```text
ai/features/DFIR-001-features.csv
```

The feature extraction pipeline includes behavioral features including Wazuh rule severity, authentication activity, encoded PowerShell, WinRM Remote Execution, Registry Run Key activity, and MITRE ATT&CK {} metadata.

### 2. Isolation Forest

Training script:

```text
ai/scripts/train_isolation_forest.py
```

Model:

```text
ai/models/isolation_forest.joblib
```

Metadata:

```text
ai/models/isolation_forest.metadata.json
```

### 3. Anomaly Scoring

Script:

```text
ai/scripts/score_anomalies.py
```

Output:

```text
ai/results/DFIR-001-anomaly-scores.csv
```

A larger anomaly score represents behavior that is more statistically unusual relative to the training dataset.

Anomaly does not mean malicious.

## Current Findings

The current DFIR-001 experiment contains 10 controlled SOC events.

The Isolation Forest model marked two events as anomalous.

The highest-ranked event was an authentication-success event rather than one of the known attack simulations.

This demonstrates an important property of unsupervised anomaly detection:

```text
rare behavior != malicious behavior
```

## Limitations

The current model is an experimental SOC analyst-triage component.

It is not a production IDS, a malware classifier, or a replacement for analyst investigation.

## Next Phase

Phase 6C will collect a larger benign Windows telemetry baseline and combine it with controlled suspicious activity.
