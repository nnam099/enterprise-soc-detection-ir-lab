# WAN Recon Through OPNsense

**Scope:** isolated `Vung_WAN` → OPNsense → `Vung_LAN` lab only.

## Prerequisites

- `OPNsense-Lab6` running (WAN `192.168.50.1`, LAN `10.0.0.1`)
- `Metasploitable2` running (target `10.0.0.5`)
- Attacker VM attached to `Vung_WAN` with a management NIC on `default`

## Run

```sh
# inside the attacker VM
sh setup-attacker.sh
sh capture-scan.sh
```

Expected:

```text
21/tcp filtered ftp
22/tcp filtered ssh
80/tcp filtered http
```

## Why `setup-attacker.sh` kills dhclient

Metasploitable's DHCP client can remove the manually assigned WAN address after a failed lease, which silently sends the scan out the management default route. The setup script prevents that and is required for a valid capture.

## Evidence

- [Firewall test](../../evidence/network-lab/firewall-test-20261026.md)
- [PCAP](../../evidence/network-lab/pcap/wan-scan-20261026.pcap)

## Do Not

- Do not run this from a production network.
- Do not expose `Vung_WAN` to the internet.
- Do not add destructive payloads to this directory.
