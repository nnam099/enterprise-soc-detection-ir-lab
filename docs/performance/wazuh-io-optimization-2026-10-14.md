# Wazuh Manager Disk I/O Performance Investigation

- **Date:** 2026-10-14
- **Environment:** Enterprise SOC Detection & IR Lab
- **Status:** Mitigated and verified
**Component:** SOC-WAZUH (192.168.50.30)

## 1. Environment

- Host: Parrot OS, QEMU/KVM, approximately 8 GB RAM
- Wazuh: 4.14.8
- SOC-WAZUH: 3 GB RAM
- Wazuh Indexer JVM heap: 256 MB initial / 512 MB maximum
- Operational limit: Maximum two concurrent VMs

## 2. Problem Statement

Wazuh Manager experienced high Disk I/O and severe
I/O Pressure while running on the resource-constrained lab.

The issue reduced the resources available for running
SOC-WIN10 alongside SOC-WAZUH.

## 3. Evidence Collected

### Process Investigation

Process: wazuh-modulesd (PID 1415 before restart)

Observed over a 5-second interval:

- Disk read: approximately 63.1 MiB/s
- Disk write: approximately 68.6 MiB/s
- Process CPU: approximately 71% lifetime average
- Guest I/O full PSI avg10: 60.13%

### Relevant Wazuh Logs

2026-10-14 14:58:26 UTC:
Vulnerability Scanner initiated a feed update.

2026-10-14 14:58:30 UTC:
Error updating feed:
[json.exception.out_of_range.401]
array index 2 is out of range.

2026-10-14 14:58:30 UTC:
Offset processing failed.
Triggered a snapshot download.

2026-10-14 14:59:21 UTC:
Vulnerability Scanner initiated another feed update.

Other IndexerConnector startup warnings were observed,
but subsequent logs confirmed successful initialization.

## 4. Investigation Assessment

Evidence confirmed that wazuh-modulesd generated
substantial Disk I/O.

Vulnerability feed processing was the leading suspect
because feed-update errors and snapshot fallback occurred.

The investigation did not isolate individual module I/O
or establish that a continuous infinite update loop existed.

## 5. Configuration Change

File: /var/ossec/etc/ossec.conf

Original:

    <vulnerability-detection>
      <enabled>yes</enabled>
      <index-status>yes</index-status>
      <feed-update-interval>60m</feed-update-interval>
    </vulnerability-detection>

Modified:

    <vulnerability-detection>
      <enabled>no</enabled>
      <index-status>yes</index-status>
      <feed-update-interval>60m</feed-update-interval>
    </vulnerability-detection>

The original configuration was backed up and verified
using cmp and SHA-256 before modification.

Backup:
  /var/backups/soc-vuln-20261014T151450Z/ossec.conf

Validation:
- wazuh-modulesd -t: Exit code 0
- wazuh-analysisd -t: Exit code 0
- Wazuh Manager restart: Exit code 0

After restart, logs confirmed:
"Vulnerability scanner module is disabled."

## 6. Before / After Validation

| Metric | Before | After |
|---|---:|---:|
| modulesd disk read, 5s average | 63.1 MiB/s | 0 MiB/s |
| modulesd disk write, 5s average | 68.6 MiB/s | 0 MiB/s |
| Guest I/O full PSI avg10 | 60.13% | 0.00% |
| Wazuh Manager | Active | Active |
| Wazuh Indexer | Active | Active |
| Wazuh Dashboard | Active | Active |

The after-change measurement was taken approximately
3.5 minutes after the Manager restart.

The results show a significant improvement during
the observation window, not a long-term performance guarantee.

## 7. Security Trade-off

Vulnerability Detection was temporarily disabled.

Consequences:
- Vulnerability assessment and feed-based detection are
  unavailable while the module is disabled.
- This mitigation does not disable the entire Wazuh Manager.
- Detection configuration tests passed.
- Full end-to-end Windows telemetry requires separate validation.

This setting is specific to the limited-resource lab
and must not be assumed appropriate for production.

## 8. Rollback Plan

If vulnerability assessment is required again:

1. Confirm sufficient system resources.
2. Back up the current configuration.
3. Restore the verified original ossec.conf.
4. Validate modulesd and analysisd configurations.
5. Restart only wazuh-manager.
6. Confirm all primary services are active.
7. Verify the vulnerability module and monitor Disk I/O.

Original backup path:
  /var/backups/soc-vuln-20261014T151450Z/ossec.conf

No VM disk, snapshot, index, or evidence files
were deleted during this mitigation.

## 9. Windows VM Resource Test

SOC-WIN10 (2 GB RAM) successfully started alongside
SOC-WAZUH but produced significant swap-out activity
during boot.

The test did not establish stable long-running operation
with both VMs.

SOC-WIN10 was shut down gracefully.

After shutdown:
- Host available memory: 2.4 GiB
- Host memory full PSI avg10: 0.00%
- SOC-WAZUH remained running

## 10. Lessons Learned

- Investigate process-level Disk I/O before changing JVM memory.
- Use logs and metrics together rather than relying on CPU alone.
- Apply one configuration change at a time.
- Preserve verified configuration backups.
- Validate both functionality and performance after restart.
- Record the security trade-off of resource-saving decisions.

## 11. Follow-up

- Reassess Wazuh Vulnerability Detection when resources allow.
- Validate Windows Agent telemetry in a controlled two-VM test.
- Continue Detection, Triage, Incident Response, and Regression Testing.
