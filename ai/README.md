# AI-Assisted SOC Analytics

Experimental anomaly scoring for analyst triage in the controlled SOC lab.

## Current v3 Evaluation

The v3 experiment uses a Windows telemetry baseline, a separate benign
validation dataset, and one controlled encoded PowerShell test event.

| Dataset | Records | Anomaly flags |
|---|---:|---:|
| Training baseline | 727 | Not reassessed during scoring reproduction |
| Benign validation | 69 | 2 |
| Controlled encoded PowerShell test | 1 | 0 |

The benign validation flag rate was approximately 2.90%.
The encoded PowerShell event was not flagged at the existing threshold.

The model therefore has a reproducible scoring result, but this test
does not demonstrate effective detection of the encoded activity.

## Pipeline and Artifacts

- [Windows event normalization](scripts/normalize_windows_events.py)
- [v3 feature matrix construction](scripts/build_feature_matrix_v3.py)
- [v3 training script](scripts/train_isolation_forest_v3.py)
- [v3 scoring script](scripts/score_events_v3.py)
- [Training manifest](models/isolation-forest-v3/training_manifest_v3.json)
- [Scoring reproduction and limitations](evaluation/repro-check-v3/README.md)

The v3 feature set excludes Wazuh rule ID, rule severity, and MITRE
metadata as direct model inputs. Normalized records retain rule metadata
for investigation context.

For v3 score_samples output, lower values indicate greater statistical
unusualness. The evaluation threshold was -0.4029047502536001.
The encoded event score was -0.4004695065499241 and was not flagged.

## Reproducibility and Dataset Separation

Rerunning scoring with the existing v3 artifacts produced exactly matching
parsed result records for both evaluation datasets.

Runtime versions and artifact hashes are preserved in the reproduction
directory. Model training was not rerun.

Source event identity checks found 727 unique training events, 69 unique
validation events, and one unique encoded test event, with no shared
event identities between these datasets.

Collection time ranges overlap. This is not a strictly chronological
holdout evaluation. Distinct event identities do not establish that
related process activity is independent.

## Earlier DFIR Experiment

An earlier experiment used 10 stored DFIR-001 records and marked two
as anomalous. Its highest-ranked event was an authentication-success
event. That experiment is separate from the v3 baseline evaluation.

- [Earlier anomaly report](results/DFIR-001-anomaly-report.md)

Results and score conventions from different experiments should not be
compared without checking their scripts and model configuration.

## Limitations and Future Work

- One encoded event is insufficient to estimate detection recall.
- Benign validation flags do not establish a production false-positive rate.
- Scoring reproduction does not establish training reproduction.
- Broader evaluation requires additional independently collected,
  reviewed benign and controlled suspicious activity.
- Any future threshold tuning needs a separate final evaluation dataset.

An anomaly flag indicates statistical unusualness, not malicious intent.
The model remains an experimental analyst-triage component.
