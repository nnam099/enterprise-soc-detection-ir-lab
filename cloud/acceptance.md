# Cloud Integration — Acceptance Criteria (Recommendation #1)

> **Status (2026-10-27):** criteria met — the branch is **deployed**; see
> [`evidence/cloud/cloud-deployment-20261027.md`](../evidence/cloud/cloud-deployment-20261027.md)
> and the checked criteria in [`architecture/cloud.md`](../architecture/cloud.md). GuardDuty
> remains out of scope (org SCP block). This checklist is retained for future re-deployments.

These criteria gate promoting the hybrid cloud branch from **PACKAGE READY** to
**DEPLOYED**. Do not claim cloud capability in the portfolio until every box is
checked and evidence is committed under `evidence/cloud/`.

| # | Criterion | How to verify | Evidence artifact |
|---|---|---|---|
| 1 | Infrastructure reproducible from code | `terraform init && terraform plan` succeeds with no manual edits | `terraform plan` output |
| 2 | No public management surface | Security group has zero inbound rules; `curl` to EC2 public IP times out | Screenshot of SG rules |
| 3 | No public `22/9200/55000` | `aws ec2 describe-security-groups` shows no ingress; dashboard stays on `soc-net` | SG/console screenshot |
| 4 | EC2 workload reachable via SSM + Tailscale | `aws ssm start-session` works; `tailscale status` shows `soc-aws-01` | Session log + Tailscale screenshot |
| 5 | Wazuh agent `SOC-AWS-01` (003) **Active** | `agent_control -l` on SOC-WAZUH shows agent 003 Active | Dashboard/CLI screenshot |
| 6 | CloudTrail data reaches Wazuh | New `wazuh-alerts-4.x-*` docs with CloudTrail source; `aws-s3` runs without credential errors | Alert JSON + `ossec.log` excerpt |
| 7 | VPC Flow Logs reach Wazuh | Flow-log objects present in S3 and decoded by Wazuh | Alert JSON + `cloud-check.sh` output |
| 8 | GuardDuty findings reach Wazuh | A finding object in `AWSLogs/<id>/GuardDuty/...` decoded by Wazuh | Finding JSON + alert |
| 9 | At least one rule fires on cloud telemetry | Built-in AWS rule (802xx) alert captured on CloudTrail/GuardDuty event | Alert screenshot/JSON |
| 10 | `cloud-check.sh` reports no FAIL | `automation/cloud-check.sh --json` returns `failed:0` | Script output |
| 11 | Topology & docs updated | [`topology.md`](../architecture/topology.md) + [`cloud.md`](../architecture/cloud.md) reflect deployed state | Git diff |
| 12 | Evidence integrity | SHA-256 manifest for all captured cloud evidence | `evidence/cloud/SHA256SUMS.txt` |
| 13 | Teardown tested | `terraform destroy` completes; no orphaned billable resources | Teardown log |

## Suggested detection map (MITRE)

| Telemetry | Built-in Wazuh rules | MITRE ATT&CK |
|---|---|---|
| CloudTrail `ConsoleLogin` / `Root` usage | 80200-series (Amazon CloudTrail) | T1078, T1530 |
| CloudTrail `IamCreateUser` / `CreateAccessKey` | 80200-series | T1136, T1098 |
| GuardDuty `Recon:EC2/PortProbeUnprotectedPort` | GuardDuty rule group | T1046 |
| VPC Flow Logs reject/spike | VPC flow rule group | T1046, T1020 |

## Outstanding / out of scope (until deployed)

- Live deployment has not been run; all files are unverified artifacts until
  `terraform apply` succeeds against a real account.
- GuardDuty findings export requires the KMS key (~$1/month); if strict $0 is
  preferred, disable GuardDuty resources in `guardduty.tf` and remove the third
  `<bucket type="guardduty">` from the wodle.
- IAM Roles Anywhere (short-lived credentials) is a hardening follow-up to
  replace the static access key.

---

*Generated with the Recommendation #1 package on 2026-10-27.*
