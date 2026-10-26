# Wazuh Syslog Integration — OPNsense (2026-10-26)

**Objective:** Forward OPNsense logs to Wazuh without adding a management NIC or renumbering the WAN.

**Result:** **PASS** — OPNsense syslog reaches Wazuh through a host UDP relay; Wazuh fired rule `100011` for a test `filterlog` message.

---

## Architecture

```text
OPNsense 26.7 (LAN 10.0.0.1)
   │  UDP 5514 (syslog-ng include)
   ▼
Parrot host relay 10.0.0.254:5514
   │  UDP 5514 (source 192.168.50.1)
   ▼
Wazuh manager 192.168.50.30:5514
   └─ <remote><connection>syslog</connection>
```

The relay is required because OPNsense has no route to `soc-net` (`192.168.50.30`). The host is attached to both `Vung_LAN` (`10.0.0.254`) and `soc-net` (`192.168.50.1`).

---

## Wazuh Configuration

Added via the Wazuh API (no SSH/sudo):

```xml
<remote>
  <connection>syslog</connection>
  <port>5514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.50.1</allowed-ips>
</remote>
```

- Full `ossec.conf` was updated with `PUT /manager/configuration` (octet-stream) and the manager restarted with `PUT /manager/restart`.
- Rules uploaded with `PUT /rules/files/lab_syslog_rules.xml?overwrite=true`.
- `logall` was temporarily enabled for the first test, then reverted to `no`.

Rule file: [`detections/wazuh/rules/100011-opnsense-syslog.xml`](../../detections/wazuh/rules/100011-opnsense-syslog.xml)

---

## OPNsense Configuration

OPNsense 26.7's syslog template did **not** apply the legacy `<syslog><remoteserver>` setting. The working method is a syslog-ng include:

`/usr/local/etc/syslog-ng.conf.d/lab.conf`:

```text
destination d_lab { network("10.0.0.254" transport("udp") port(5514)); };
log { source(s_all); destination(d_lab); };
```

Apply:

```sh
configctl syslog restart
```

The include survives template regeneration, unlike appending directly to the main config.

---

## Relay

Host: [`automation/wazuh-syslog-relay.py`](../../automation/wazuh-syslog-relay.py)

```sh
python3 automation/wazuh-syslog-relay.py
```

It listens on UDP 5514 and forwards to `192.168.50.30:5514`, logging each packet and its source.

---

## Evidence

### Relay log — OPNsense connected to the host

```text
10.0.0.1:20081 b"<45>Oct 26 04:59:36 OPNsense.internal syslog-ng[54805]: Syslog connection established; fd='19', server='AF_INET(10.0.0.254:5514)', local='AF_INET(0.0.0.0:0)'"
10.0.0.1:20081 b'<13>Oct 26 04:59:43 OPNsense.internal root[48856]: filterlog LABREMOTE4\n'
```

### Wazuh alert

```json
{
  "predecoder": {
    "hostname": "OPNsense.internal",
    "program_name": "root",
    "timestamp": "Oct 26 04:59:43"
  },
  "rule": {
    "id": "100011",
    "level": 3,
    "description": "LAB OPNsense filterlog event",
    "groups": ["lab", "syslog"]
  },
  "full_log": "Oct 26 04:59:43 OPNsense.internal root[48856]: filterlog LABREMOTE4",
  "location": "192.168.50.1",
  "@timestamp": "2026-10-26T04:59:44.001Z"
}
```

- Raw relay log: [`logs/relay-20261026.log`](logs/relay-20261026.log)
- Wazuh alert JSON: [`logs/wazuh-syslog-alert-20261026.json`](logs/wazuh-syslog-alert-20261026.json)
- Console screenshot: [`screenshots/phase7-network/opnsense-syslog-relay-20261026.png`](../../screenshots/phase7-network/opnsense-syslog-relay-20261026.png)

SHA-256: [`logs/SHA256SUMS-syslog.txt`](logs/SHA256SUMS-syslog.txt)

---

## Limitations

| Item | Status |
|---|---|
| Transport | UDP syslog, unencrypted — lab only |
| Relay | Python process on the host; must be running for forwarding |
| OPNsense UI remote logging | Legacy `remoteserver` ignored by 26.7 template; syslog-ng include used instead |
| Wazuh parsing | Lab rules match `filterlog` / test string; no full OPNsense decoder |
| Source attribution | Events appear as manager events (`agent 000`), location `192.168.50.1` (relay) |
| Suricata alerts to Wazuh | Not forwarded yet; only OPNsense syslog |
| TLS/netflow | Not configured |

## Cleanup / Reproduce

Stop the relay with `pkill -f wazuh-syslog-relay.py`. To reproduce, start the relay, ensure the syslog-ng include exists, and send a test:

```sh
logger filterlog LABREMOTE
```

Then query the Wazuh alerts index for `LABREMOTE`.

## Suricata Forwarding

The same relay also carries Suricata `eve.json`; see [`suricata-wazuh-20261026.md`](suricata-wazuh-20261026.md).
