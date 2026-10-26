# SOC Lab IP Plan

## Address Allocation

| Node (libvirt domain) | Hostname / Agent name | IP | MAC | Role |
|---|---|---|---:|---|
| `SOC-DC01` | `DC01.soc-lab.local` (AD) · agent `SOC-DC01` (002) | 192.168.50.10 | 52:54:00:7a:6b:db | Windows Server 2022, AD DS + DNS |
| `SOC-WIN10` | `SOC-WIN10` (agent 001) | 192.168.50.20 | 52:54:00:09:4e:58 | Windows 10 endpoint, Sysmon, Wazuh Agent |
| `SOC-WAZUH` | `soc-wazuh` | 192.168.50.30 | 52:54:00:fe:8a:46 | Wazuh Manager, Indexer & Dashboard v4.14.8 |
| Parrot host | — | 192.168.50.1 | 52:54:00:04:7f:06 | Hypervisor host, NAT gateway, analyst workstation |
| DHCP pool | — | 192.168.50.100–200 | — | Temporary lab VMs only |

All three lab VMs use **static IP addresses**; the DHCP pool is reserved for temporary VMs. An empty `virsh net-dhcp-leases soc-net` output is therefore expected and does not indicate a fault.

---

## DNS

| Record | Value |
|---|---|
| `DC01.soc-lab.local` (A) | 192.168.50.10 |
| `soc-lab.local` (A) | 192.168.50.10 |
| `_ldap._tcp.dc._msdcs.soc-lab.local` (SRV) | `dc01.soc-lab.local:389` |
| `_kerberos._tcp.soc-lab.local` (SRV) | `dc01.soc-lab.local:88` |
| AD `defaultNamingContext` | `DC=SOC-LAB,DC=LOCAL` |
| AD `domainControllerFunctionality` | `7` (Windows Server 2016+) |

> Naming note: the libvirt domain is named `SOC-DC01` while the Windows/AD computer name is `DC01`. Both refer to the same VM. Use `DC01.soc-lab.local` for DNS/LDAP/Kerberos operations.

---

## Service Exposure (verified 2026-10-26)

| Host | Ports observed open | Notes |
|---|---|---|
| `SOC-DC01` | 53/tcp, 88/tcp, 135/tcp, 389/tcp, 445/tcp, 3389/tcp, 5985/tcp | Full AD DS role; RDP and WinRM enabled |
| `SOC-WIN10` | 5985/tcp | WinRM listener; may take 2–3 minutes after boot. RDP is disabled. |
| `SOC-WAZUH` | 22/tcp, 443/tcp, 1514/tcp, 1515/tcp, 55000/tcp | Indexer `9200` is bound to localhost only and is intentionally not exposed to the lab network |

---

## Connectivity Testing Notes

- **Do not use ICMP as the primary check for Windows hosts.** Windows Firewall blocks inbound echo requests by default. Use ARP resolution instead:

  ```bash
  ping -c 1 -W 1 192.168.50.20 >/dev/null 2>&1
  ip neigh show 192.168.50.20   # expect REACHABLE / STALE / DELAY
  ```

- **WinRM (5985)** is the reliable service-level check for the Windows endpoint. It can take 2–3 minutes after boot to listen, so the check script retries. Its state reflects service startup and firewall profile, not domain membership on its own.
- **Wazuh health** is checked at three levels: TCP `443` (dashboard), TCP `55000` (API returns `401` without credentials), and TCP `1514/1515` (agent enrollment and ingest).
- **Wazuh agent health** is confirmed by new documents in the `wazuh-alerts-4.x-*` index with `agent.id = 001` (SOC-WIN10), not by ICMP.

Run the repeatable check with [`automation/lab-connectivity-check.sh`](../automation/lab-connectivity-check.sh).

---

## Known Configuration Drift

| Item | Detail |
|---|---|
| `SOC-WIN10` NIC model | Current libvirt definition uses `virtio`; the 2026-10-07 XML backup recorded `e1000e`. The guest has the virtio driver and networking works. Backups are historical and should not be treated as current state. |
| AD hostname vs VM name | VM `SOC-DC01` ↔ hostname `DC01` (documented above). |
