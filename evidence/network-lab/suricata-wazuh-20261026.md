# Suricata eve.json → Wazuh (2026-10-26)

**Objective:** Forward Suricata alerts from OPNsense to Wazuh and confirm they are parsed as structured JSON events.

**Result:** **PASS** — 12 Suricata alerts reached Wazuh, decoded by the built-in `json` decoder and matched by rule `86601` (`Suricata: Alert - ...`).

---

## Architecture

```text
Suricata 8.0.6 (OPNsense, vtnet1)
   │ writes /var/log/suricata/eve.json
   ▼
syslog-ng  source s_suricata (file, flags(no-parse))
   │ UDP 5514
   ▼
Parrot host relay 10.0.0.254:5514
   │ UDP 5514 (source 192.168.50.1)
   ▼
Wazuh manager 192.168.50.30:5514
   └─ decoder: json  ·  rule 86601
```

The OPNsense syslog-ng include now tails both the system log source and `eve.json`:

```text
destination d_lab { network("10.0.0.254" transport("udp") port(5514)); };
log { source(s_all); destination(d_lab); };
source s_suricata { file("/var/log/suricata/eve.json" follow-freq(1) flags(no-parse)); };
log { source(s_suricata); destination(d_lab); };
```

---

## Evidence

Query: alerts with `rule.id = 86601` (12 hits).

```json
{
  "@timestamp": "2026-10-26T05:12:37.186Z",
  "rule": {
    "id": "86601",
    "level": 3,
    "description": "Suricata: Alert - LAB WAN scan to firewall",
    "groups": ["ids", "suricata"]
  },
  "decoder": {"name": "json"},
  "location": "192.168.50.1",
  "data": {
    "event_type": "alert",
    "in_iface": "vtnet1",
    "src_ip": "192.168.50.10",
    "dest_ip": "192.168.50.1",
    "dest_port": "443",
    "proto": "TCP",
    "alert": {
      "signature_id": "1000002",
      "signature": "LAB WAN scan to firewall",
      "severity": "3",
      "action": "allowed",
      "gid": "1",
      "rev": "1"
    }
  }
}
```

- 12 alerts captured, all from the WAN scan.
- `full_log` is `null` because Wazuh parsed the event as JSON, not as raw syslog.
- The custom rule `100020` (`<match>"event_type":"alert"</match>`) was **not needed** and was deleted; the built-in Suricata rule `86601` is the correct detection.

### Artifacts

| File | SHA-256 |
|---|---|
| [`logs/wazuh-suricata-20261026.json`](logs/wazuh-suricata-20261026.json) | `ef7671d3737a5a0b1ed3c6e1323ee19138054efbf4dbcd9bb4daaffb1bf38fd1` |
| [`logs/relay-suricata-20261026.log`](logs/relay-suricata-20261026.log) | `db005385256bd97d90edf5a20bee5cd1d4e966abc49eb14409d87be2ff0a47a5` |

Screenshot: [`screenshots/phase7-network/opnsense-suricata-eve-20261026.png`](../../screenshots/phase7-network/opnsense-suricata-eve-20261026.png)

---

## How to Reproduce

1. Start Suricata on OPNsense:
   ```sh
   sh /root/startids.sh
   ```
2. Ensure the syslog-ng include tails `eve.json` and restart syslog:
   ```sh
   configctl syslog restart
   ```
3. Start the host relay:
   ```sh
   python3 automation/wazuh-syslog-relay.py
   ```
4. Generate WAN traffic (e.g., `nmap` from `Attacker-MSF`).
5. Query Wazuh for `rule.id:86601`.

---

## Limitations

| Item | Status |
|---|---|
| Transport | UDP syslog, unencrypted — lab only |
| Relay | Manual host process; must be running |
| Replay behaviour | syslog-ng reads `eve.json` from the beginning on restart, so old alerts are re-sent (duplicates possible) |
| Log rotation | Not configured; a real deployment should rotate and track offsets |
| Parser | Built-in Wazuh Suricata decoder (`json`) + rule `86601` |
| Other eve types | Only `event_type=alert` is asserted here; flow/DNS/HTTP events are forwarded but not tuned |
| Wazuh `logall` | `no` (performance); alerts only |
| TLS | Not configured |

## Cleanup

Suricata, the relay, and all VMs were stopped after validation. The syslog-ng include remains on OPNsense for future runs.
