# DFIR-002 — Evidence Manifest and Integrity

## Acquisition Package

Collection directory on WIN10-01:

`C:\SOC-Forensics\DFIR-002-20261009T012247Z`

| Artifact group | Count |
|---|---:|
| Security EVTX | 1 |
| Sysmon EVTX | 1 |
| PowerShell EVTX | 1 |
| Prefetch files | 255 |
| Acquisition metadata JSON | 1 |
| Individual collection CSV manifests | 2 |
| **Files covered by aggregate hash manifest** | **261** |

The package also contains `SHA256SUMS.txt`, which is not
self-included in its own manifest.

## Verification

- EVTX readback: 3/3 PASS.
- EVTX SHA-256 verification: 3/3 PASS.
- Prefetch post-copy SHA-256 verification: 255/255 PASS.
- Aggregate manifest verification: 261/261 PASS.
- Reported hash mismatches: 0.

## Derived Evidence

- Path: `C:\SOC-Forensics\DFIR-002-Analysis\native-correlation.json`
- SHA-256:
  `A9C52CF34F81A5E6C6C784989578D987C1871ED907FB46ED0E1B3D97776C508B`

The derived file is outside the 261-file acquisition manifest.

## Evidence Handling

Raw native EVTX and Prefetch data are intentionally excluded from
this public repository because they may contain sensitive information.

The aggregate manifest was generated after collection.
Hash verification proves agreement with that recorded baseline;
it does not independently prove original source authenticity,
forensic completeness, or an uninterrupted chain of custody.

## Known Gap

`Amcache.hve` was present but could not be copied because it was
locked by Windows. No Amcache acquisition is claimed.
