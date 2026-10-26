# OPNsense IDS Service + Wazuh (2026-10-26)

**Objective:** Run Suricata through the native OPNsense IDS service instead of a manual process, and confirm alerts still reach Wazuh.

**Result:** **PASS** — `service suricata status` reports running (PID 53430), two new `eve.json` alerts were generated, and Wazuh now holds **14** Suricata alerts (rule `86601`).

---

## Configuration

### OPNsense IDS

Enabled via the OPNsense config model (`OPNsense.IDS.general`):

| Key | Value |
|---|---|
| `enabled` | `1` |
| `interfaces` | `wan` |
| `model` | `pcap` |
| `promisc` | `1` |
| `detect.profile` | `medium` |
| `defaultPacketSize` | `1514` |
| `MPMAlgo` | `ac` |

Service runtime (`/etc/rc.conf.d/suricata`):

```text
suricata_setup="/usr/local/opnsense/scripts/suricata/setup.sh"
suricata_enable="YES"
suricata_flags="-D"
# IDS mode, pcap live mode
suricata_interface="vtnet1"
```

Rules are loaded from `/root/lab.rules` via `/usr/local/etc/suricata/installed_rules.yaml`.

Start/status:

```sh
service suricata start
service suricata status
# suricata is running as pid 53430.
```

### Forwarding

`/usr/local/etc/syslog-ng.conf.d/lab.conf` tails `eve.json` and sends it to the host relay, which forwards to Wazuh (`192.168.50.30:5514`). Wazuh parses the JSON with decoder `json` and fires the built-in Suricata rule `86601`.

---

## Evidence

New alerts from the IDS service (OPNsense `eve.json`):

```text
2026-10-26T05:31:50.907255+0000  signature_id=1000002  LAB WAN scan to firewall
  src=192.168.50.10:40824  dst=192.168.50.1:443  in_iface=vtnet1

2026-10-26T05:31:51.896270+0000  signature_id=1000002  LAB WAN scan to firewall
  src=192.168.50.10:40825  dst=192.168.50.1:443  in_iface=vtnet1
```

Wazuh query `rule.id:86601`:

```text
total = 14
latest @timestamp = 2026-10-26T05:31:52Z
rule = "Suricata: Alert - LAB WAN scan to firewall"
decoder = json
location = 192.168.50.1
```

Artifacts:

| File | SHA-256 |
|---|---|
| [`logs/wazuh-ids-service-20261026.json`](logs/wazuh-ids-service-20261026.json) | `3a08198fcd27749cdc9d4ef0c45afbf5f90c6ebef44426cfba6a9f7c45638f95` |
| [`logs/relay-ids-service-20261026.log`](logs/relay-ids-service-20261026.log) | `fb0353bb4b49164f14dcb590d7e09d9ef17635ce269204fdc2e490a35bc9c64b` |

Screenshot: [`screenshots/phase7-network/opnsense-ids-service-20261026.png`](../../screenshots/phase7-network/opnsense-ids-service-20261026.png)

---

## Notes / Limitations

| Item | Status |
|---|---|
| Service | Native OPNsense IDS service (`service suricata`) |
| Interface | Runtime uses `vtnet1` (pcap); the generated `suricata.yaml` still contains a netmap `interface: default` block that is not used |
| Rules | Custom `/root/lab.rules`; no OPNsense-managed ET rulesets |
| IPS mode | Not enabled; IDS/pcap only |
| Relay | Host process required for Wazuh forwarding |
| Replay | syslog-ng may resend older `eve.json` lines after restart |
| GUI | Service enabled via config/PHP; GUI/form parity not verified |

## Cleanup

The service was stopped, the relay and all VMs were shut down after validation. The IDS configuration and custom rules remain on the OPNsense disk for future runs.
