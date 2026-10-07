# Isolation Forest v3 Scoring Reproducibility

## Outcome

Scoring was rerun using the existing v3 vectorizer, model, and training
manifest. Parsed result records exactly matched the previously stored
benign validation and encoded PowerShell results.

This verifies scoring reproducibility in the recorded environment.
Model training was not rerun.

## Results

| Dataset | Events | Anomaly flags |
|---|---:|---:|
| Benign validation | 69 | 2 |
| Controlled encoded PowerShell test | 1 | 0 |

The threshold was -0.4029047502536001.
The encoded PowerShell score was -0.4004695065499241 and was not flagged.

The benign validation flag rate was approximately 2.90%.
These small controlled datasets do not establish general detection
performance or a production false-positive rate.

## Dataset Separation

A check of computer, channel, provider, event ID, event record ID,
and endpoint system time found:

- Training: 727 records and 727 unique event identities.
- Validation: 69 records and 69 unique event identities.
- Encoded test: 1 record and 1 unique event identity.
- No shared event identities between these datasets.

Collection time ranges overlap. This is not a strictly chronological
holdout evaluation. Event identity separation alone does not establish
independence between related process activity.

## Limitations

- One encoded test event is insufficient to estimate detection recall.
- The controlled encoded event was not flagged at the existing threshold.
- Scoring reproducibility does not verify training reproducibility.
- No threshold change was made during this check.

## Artifacts

The JSON reports identify the input, vectorizer, model, and training
manifest paths and their SHA-256 values.

environment.json records the runtime package versions.
SHA256SUMS.txt covers the artifacts in this directory.
