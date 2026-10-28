# Cloud Integration (Hybrid — Recommendation #1)

**Status:** DEPLOYED (core path verified 2026-10-27). The hybrid cloud branch is live:
an AWS Free-Tier EC2 workload reports to the on-prem Wazuh SIEM over Tailscale, and AWS
native logs (CloudTrail + VPC Flow Logs) stream to S3 and are pulled by the on-prem manager
via the `aws-s3` wodle. GuardDuty is **blocked** by an org Service Control Policy (see
[GuardDuty](#guardDuty-blocked-by-scp)).

**Provisioning note:** the deployed resources were created **manually via the AWS Management
Console + AWS CLI**, not via Terraform. The [`cloud/terraform/`](../cloud/terraform/) package
is retained as a reference implementation of the same topology but does **not** describe the
live environment.

**Evidence:** [`evidence/cloud/cloud-deployment-20261027.md`](../evidence/cloud/cloud-deployment-20261027.md)

---

## Chosen Design — Option D: On-Prem Wazuh + AWS workload & native logs

The on-prem cluster (`SOC-DC01`, `SOC-WIN10`, `SOC-WAZUH`) is unchanged. The AWS branch adds
three telemetry planes that all converge on the same on-prem Wazuh manager:

```text
                       ┌────────────────────── AWS (ap-southeast-2) ──────────────────────┐
 CloudTrail  ────────► │  S3: soc-hybrid-logs-411109262083                                │
 VPC Flow Logs ──────► │      ▲  pulled by SOC-WAZUH (wodle aws-s3, IAM wazuh-reader)     │
                       │      │                                                           │
                       │  EC2 SOC-AWS-01 (t3.micro, Ubuntu 24.04) ── Wazuh agent 003 ───┐ │
                       └───────────────────────────────────────────────────────────────┼─┘
                                                                       Tailscale (outbound)
   On-Prem soc-net ────────────────────────────────────────────────────┼───────────────────
   SOC-DC01 .10  ·  SOC-WIN10 .20 (001)  ·  SOC-WAZUH .30 ◄───────────┘
```

| Component | Live value |
|---|---|
| EC2 workload | `SOC-AWS-01`, `t3.micro`, Ubuntu 24.04.5 LTS, VPC `SOC-LAB-VPC` (10.20.0.0/16) |
| Tailscale mesh | `soc-aws-01` 100.101.95.40 · `soc-wazuh` 100.80.140.56 · `parrot-soc` 100.89.43.28 |
| Wazuh agent | `003` `SOC-AWS-01` → manager over Tailscale (Active) |
| Control-plane logs | CloudTrail `soc-hybrid-trail` → S3 |
| Network logs | VPC Flow Logs `fl-0422e945f4c1d8625` → S3 |
| Threat detection | GuardDuty — **blocked by SCP** |
| SIEM pull | `wodle aws-s3` (cloudtrail + vpcflow) on SOC-WAZUH |
| Custom detection | Rule `100508` (level 10, IAM CreateUser/CreateAccessKey, MITRE T1136.001/T1098.001) |

### Why this over a cloud Wazuh manager

| Goal | Outcome |
|---|---|
| Cost control | ~$0–1.5/mo (Free-Tier EC2 + gp3 EBS); no 4–8 GB EC2 for Indexer/Manager |
| Hybrid telemetry | Endpoint/AD (on-prem) + Linux workload (EC2) + AWS control plane in one SIEM |
| Network security | Zero inbound security-group rules; no public 22/9200/55000 |
| Least privilege | Scoped S3 bucket policy; Wazuh reader with `GetObject`/`ListBucket` only |
| Detection | Rule 100508 (level 10) validated via `wazuh-logtest` |

---

## Non-Negotiable Security Requirements

| Requirement | Rule | Implemented |
|---|---|---|
| Management access | No public SSH; SSM/Tailscale | SG zero inbound; SSH scoped to analyst IP |
| Key management | Keys never in Git | keys live on hosts (mode 600); chat-exposed keys flagged for rotation |
| Dashboard exposure | Stays on-prem; no public 9200 | unchanged on-prem |
| Agent traffic | TLS enrollment over Tailscale | agent 003 → 100.80.140.56:1514/1515 |
| Logging | CloudTrail + Flow Logs → S3 | live; GuardDuty blocked (SCP) |
| Cost control | Free Tier + lifecycle | 90-day S3 lifecycle, budget note |
| Evidence | Screenshots/logs + manifest | `evidence/cloud/cloud-deployment-20261027.md` |

---

## Acceptance Criteria

- [x] Cloud resources reachable and reproducible (manual runbook + reference Terraform).
- [x] Security group allows zero inbound; management via SSM/Tailscale.
- [x] No public `22`, `9200`, or `55000`.
- [x] EC2 workload reachable over Tailscale.
- [x] Wazuh agent `SOC-AWS-01` (003) **Active**.
- [x] CloudTrail + VPC Flow Logs reach Wazuh via `aws-s3` (8 + 3 events in archives).
- [x] Detection rule fires on cloud telemetry (built-in 80202 live; custom 100508 via logtest).
- [x] [`topology.md`](topology.md) updated with the deployed branch.
- [ ] GuardDuty enabled — **blocked by SCP; out of scope**.
- [ ] SHA-256 evidence manifest — pending.

---

## GuardDuty Blocked by SCP

The account (`411109262083`) is a member of AWS Organization `o-cwcc4rfgqn`. A Service Control
Policy (`p-zimswo7d`) explicitly denies GuardDuty actions, so GuardDuty cannot be enabled from
this account. Resolution requires the org management account to lift the deny. Until then,
CloudTrail + VPC Flow Logs provide control-plane and network telemetry.

---

## Current State

| Item | Status |
|---|---|
| Cloud account / region | `411109262083` / `ap-southeast-2` |
| Deployed cloud resources | EC2, S3, CloudTrail, Flow Logs, IAM reader, Tailscale mesh |
| Cloud evidence in repo | [`evidence/cloud/cloud-deployment-20261027.md`](../evidence/cloud/cloud-deployment-20261027.md) |
| On-prem lab status | Operational; connectivity verified 2026-10-26 |

---

## Rejected Alternatives (kept for reference)

- **Option A — Cloud Wazuh manager:** higher cost, public-dashboard risk; rejected in favor of keeping the SIEM on-prem.
- **Option B — Cloud jump host only:** no SIEM value.
- **Option C — Fully local:** does not demonstrate hybrid posture.
