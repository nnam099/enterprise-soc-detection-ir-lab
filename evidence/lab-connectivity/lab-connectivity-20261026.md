# Lab Connectivity Validation — 2026-10-26

**Scope:** Verify that all three lab VMs boot, that `soc-net` connectivity matches the IP plan, that AD DS/DNS/Kerberos/LDAP are operational, and that the Wazuh dashboard and agent ingest work with live telemetry.

**Host:** Parrot Security 7.4, 12 vCPU, 7.5 GiB RAM, QEMU 10.0.13 / libvirt 11.3.0
**Operator:** `nnam09` (local, authorized)
**Method:** `virsh start` / `virsh shutdown` only. No VM XML, network, rule, or snapshot was modified.
**Result:** **PASS (3/3 VMs)**

---

## 1. Resource Rotation Used

| Phase | VMs running | Duration |
|---|---|---|
| Detection Mode | SOC-WAZUH + SOC-WIN10 | ~3 min |
| Identity Mode | SOC-WIN10 + SOC-DC01 | ~3 min |

No more than two VMs ran concurrently, consistent with [`resource-modes.md`](../../architecture/resource-modes.md).

---

## 2. SOC-WAZUH — 192.168.50.30

```text
ping:   3/3 received, 0% loss, avg 0.210 ms
ports:  22 OPEN, 443 OPEN, 1514 OPEN, 1515 OPEN, 55000 OPEN, 9200 closed
HTTPS:  302 Found -> /app/login
        osd-name: soc-wazuh
        x-frame-options: sameorigin
API:    401 Unauthorized (unauthenticated request, expected)
        Server: Wazuh
        strict-transport-security: max-age=63072000; includeSubdomains
```

| Check | Result |
|---|---|
| Dashboard reachable over HTTPS | PASS |
| Wazuh API responding (`401` without session) | PASS |
| Agent ingest ports `1514/1515` | PASS |
| Indexer `9200` not exposed to lab network | PASS (by design) |

### Wazuh dashboard authentication and live ingest

- Dashboard login with the lab `admin` account returned `HTTP 200` and role `all_access`.
- The credential is **not stored in this repository** and is not reproduced in this document.
- After `SOC-WIN10` booted, the Wazuh indexer contained **42 new documents** for `agent.id = 001` in a ~3-minute window.

Latest sample (UTC):

```text
2026-10-26T01:16:14.772Z | SOC-WIN10 | 192.168.50.20 | rule 92217 L6 | Executable dropped in Windows root folder
2026-10-26T01:15:52.366Z | SOC-WIN10 | 192.168.50.20 | rule 60642 L3 | Software protection service scheduled successfully
2026-10-26T01:15:52.053Z | SOC-WIN10 | 192.168.50.20 | rule 92031 L3 | Discovery activity executed
```

Wazuh manager start event:

```text
2026-10-26T01:13:18.465Z | agent 000 soc-wazuh | rule 502 L3 | Wazuh server started
```

> The rule 92217/92031 hits above are ordinary Windows boot/update activity captured as telemetry. They were not triaged as an incident and are cited only as proof of ingestion.

---

## 3. SOC-WIN10 — 192.168.50.20

```text
console:  Windows lock screen, 08:00 Monday 26 October
ARP:      52:54:00:09:4e:58 REACHABLE
ping:     blocked (Windows Firewall default; not a fault)
DHCP:     no lease (static IP .20, expected)
WinRM:    5985 OPEN -> HTTP/1.1 405, Server: Microsoft-HTTPAPI/2.0
RDP:      3389 closed (disabled)
SMB/RPC:  445/135 blocked by firewall profile
```

| Check | First sample (~2 min after boot) | Repeat sample |
|---|---|---|
| ARP reachability | PASS | PASS |
| WinRM 5985 | closed | **OPEN** |
| Wazuh agent alerts | — | **42 new** |

The WinRM listener appeared between two samples taken seconds apart, reflecting Windows service startup and firewall-profile timing rather than domain membership alone. The check script retries TCP checks three times before reporting a failure.

---

## 4. SOC-DC01 — 192.168.50.10

```text
ARP:   52:54:00:7a:6b:db
ports: 53 OPEN, 88 OPEN, 389 OPEN, 445 OPEN, 3389 OPEN, 5985 OPEN, 135 OPEN
DNS:   soc-lab.local -> 192.168.50.10
       _ldap._tcp.dc._msdcs.soc-lab.local SRV -> dc01.soc-lab.local:389
       _kerberos._tcp.soc-lab.local SRV      -> dc01.soc-lab.local:88

LDAP rootDSE:
  dnsHostName: DC01.SOC-LAB.LOCAL
  domainControllerFunctionality: 7
  defaultNamingContext: DC=SOC-LAB,DC=LOCAL
```

| Check | Result |
|---|---|
| AD DS responding (LDAP rootDSE) | PASS |
| DNS A + SRV records | PASS |
| Kerberos (88) | PASS |
| SMB/RPC/WinRM/RDP | PASS |
| Domain functional level | 7 (Windows Server 2016+) |

A single reverse-DNS (PTR) query timed out while the DC was still booting; forward A and SRV records were correct. PTR/reverse-zone validation remains open.

---

## 5. Resource Observations

| Mode | Host RAM used | Swap used | Load | Outcome |
|---|---|---|---|---|
| WAZUH + WIN10 | ~6.0–6.3 GiB | ~5–6.3 GiB | ~1.3–2.4 | Stable, no OOM |
| WIN10 + DC01 | ~6.1 GiB | ~5.0 GiB | ~1.3 | Stable |

The 8 GB host remains usable but relies on swap. Close desktop applications (browser, chat clients) before running a two-VM mode.

---

## 6. Limitations

- No interactive domain user logon or Kerberos TGT was performed.
- Wazuh API token issuance was not tested; the dashboard session was used instead.
- RDP to `SOC-WIN10` is disabled and was not tested.
- Reverse DNS (PTR) not validated.
- No packet capture was taken (host lacks `CAP_NET_RAW` for `tcpdump` without elevation).

---

## 7. Final State

```text
SOC-DC01   shut off
SOC-WIN10  shut off
SOC-WAZUH  shut off
soc-net    active, autostart yes, 0 DHCP leases
Host RAM   2.7 GiB used / 4.8 GiB available
Disk       90% used (52 GB free)
```

All VMs were shut down gracefully. Snapshots (`DC01-DOMAIN-READY`, `WIN10-DOMAIN-JOINED`, `WAZUH-INSTALLED`) were not modified.

---

## 8. Reproduce

```bash
# start a supported mode first, then:
./automation/lab-connectivity-check.sh

# machine-readable output
./automation/lab-connectivity-check.sh --json
```

### Script validation on 2026-10-26

| Mode | VMs running | Result |
|---|---|---|
| Detection Mode | SOC-WAZUH + SOC-WIN10 | `PASS=9 FAIL=0 SKIP=2`, exit `0` |
| Identity Mode | SOC-DC01 + SOC-WIN10 | `PASS=11 FAIL=0 SKIP=2`, exit `0` |
| No VMs | none | exit `3` with guidance message |

The script was run against both supported two-VM rotations and correctly skipped the powered-off VM. It performs no writes and requires no credentials.
