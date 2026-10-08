# SOC-INC-001 — Lab Completion and Closure Assessment

## Decision

Decision date: 2026-10-08.

SOC-INC-001 is closed as an educational exercise within the verified
scope of the documented investigation, separate response exercises,
and scoped recovery checks. The evidence limitations below are accepted
for this lab closure. No real compromise, fully clean endpoint, or
complete production incident lifecycle is asserted.

The eleven-sample monitoring window is accepted for this exercise.
Longer monitoring and application-specific recovery checks remain
follow-up work if the lab scope is expanded.

## Verified Work

- Original controlled observations: WinRM execution, encoded PowerShell,
  and Registry Run Key modification.
- Separate process containment replay with post-action absence checks.
- Separate AD account disable and restoration with DC audit evidence.
- Run Key absence under the original user SID.
- Eleven sampled checks over approximately five minutes fourteen seconds.
- Post-restoration domain authentication and target-identity process creation.
- October 8 desktop session under the target SID, successful DC Kerberos
  authentication, and profile file creation/readback.
- Four live encoded PowerShell validation tests.

The October response exercises are separate from the September simulation.

## Accepted Evidence Limitations

- Historical Run Key deletion time and actor remain unverified.
- Sampled monitoring does not prove continuous absence.
- Sysmon Event 5 process termination evidence remains unverified.
- Existing session revocation and recovery of all applications remain
  unverified. October 8 desktop and profile file checks passed within
  their documented scope.

## Separate Follow-up Work

INC-002 has verified live before/after results for the PowerShell file
creation cases. Its intended WebView2 level 3 branch remains unverified
through matching live telemetry.

DFIR-001 is a separate controlled evidence review. Isolation Forest v3
scoring was reproduced; the single encoded test event was not flagged.
These results do not establish operational detection effectiveness.

## Preservation Status

Repository documentation and investigation evidence are retained in Git.

On 2026-10-08, standalone QCOW2 backups of SOC-DC01, SOC-WAZUH,
and SOC-WIN10 were completed on the external HDD with the VMs shut off.
Each backup merges the active overlay and its backing chain.
The three images occupy approximately 86 GiB in total.

Backup directory:
`SOC-Lab-Backup-20261008-1dYQ67`

For each image, `qemu-img check` reported no errors and
`qemu-img compare` against the source chain reported
`Images are identical` with exit code 0.
These results were observed in operator-provided console output;
separate raw verification logs were not saved during these commands.

The backup includes original domain XML, prepared restore XML,
libvirt network XML and network status records, and BACKUP-README.txt.
External snapshot history is not preserved by the flattened images.
Restore boot testing has not been performed.

The prepared restore XML requires path and identity review before use.
Its default disk paths overlap the original backing-file paths;
restoration must not overwrite those files.
Original VM disks and backing files remain retained on the host.

Before backup, the HDD exFAT filesystem was repaired. A subsequent
read-only filesystem check reported clean with exit code 0.
This does not establish the physical health of the HDD.

The HDD was synced, unmounted, and powered off after backup.
On 2026-10-08, the temporary SSD rescue copy
`hdd-rescue-20261008-5ee8Xu` was deleted at the user's request.
The rescued personal files and CAPE archive are retained on the HDD;
the temporary SSD copy is no longer available.

## References

- [Capstone report](capstone-report.md)
- [Recovery verification](recovery-verification.md)
- [Process response replay](response-replay.md)
- [Account response](account-response.md)

## Supporting Final Status Screenshot

The screenshot records repository synchronization and powered-off VMs
at commit ae0298c, before this screenshot documentation was committed.
It does not establish completion of a VM disk backup.

![Repository and VM status](../../screenshots/phase4-incident/71-soc-lab-final-repository-and-vm-status.png)
