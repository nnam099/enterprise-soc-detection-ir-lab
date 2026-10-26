# Attack Simulations (Authorized Lab Only)

These scripts are for the isolated `Vung_WAN` / `Vung_LAN` lab only. They are non-destructive and must never be run against systems you do not own or have written authorization to test.

## WAN Recon Through OPNsense

Directory: [`wan-recon/`](wan-recon/)

| Script | Purpose |
|---|---|
| `setup-attacker.sh` | Stop DHCP from clearing the static WAN address and add the route to `10.0.0.0/24` |
| `capture-scan.sh` | Capture SYN traffic while scanning the LAN target through OPNsense |

Expected result: TCP 21/22/80 are `filtered` from `192.168.50.10` while the same ports are `open` from the LAN side (`10.0.0.254`).

Evidence: [`evidence/network-lab/firewall-test-20261026.md`](../evidence/network-lab/firewall-test-20261026.md)

## LAN Exploitation

Directory: [`lan-exploit/`](lan-exploit/)

| Script | Purpose |
|---|---|
| `vsftpd_backdoor.py` | Trigger CVE-2011-2523 on the lab Metasploitable target and run non-destructive commands |

Evidence: [`evidence/network-lab/exploit-vsftpd-20261026.md`](../evidence/network-lab/exploit-vsftpd-20261026.md)

## Safety

- Only run while `Vung_WAN` is isolated (no forward/NAT).
- Do not run SOC VMs at the same time on the 8 GB host.
- Do not add exploits or destructive payloads to this directory.
