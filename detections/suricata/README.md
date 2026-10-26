# Suricata Lab Rules

Custom rules used to validate IDS visibility during the WAN-side scan exercise.

## Rules

| SID | Alert | Purpose |
|---|---|---|
| 1000001 | LAB WAN scan to target | SYN from `192.168.50.10` to `10.0.0.5` |
| 1000002 | LAB WAN scan to firewall | SYN from `192.168.50.10` to `192.168.50.1` |
| 1000003 | LAB WAN ping | ICMP echo from the WAN attacker |

## Run on OPNsense (manual, lab only)

OPNsense 26.7 ships Suricata 8.0.6. The service was started manually on the WAN interface:

```sh
# copy lab.rules to /root/lab.rules on OPNsense
suricata -T -c /usr/local/etc/suricata/suricata.yaml -i vtnet1 -S /root/lab.rules
suricata -c /usr/local/etc/suricata/suricata.yaml -i vtnet1 -S /root/lab.rules -l /var/log/suricata -D
```

Check alerts:

```sh
grep LAB /var/log/suricata/eve.json
```

Stop:

```sh
killall suricata
```

## Notes

- This bypasses the OPNsense IDS service and its ruleset management; it is a lab validation, not a production deployment.
- `installed_rules.yaml` was created to satisfy the OPNsense Suricata config include and points to `/root/lab.rules`.
- Alerts are local to OPNsense; they are not forwarded to Wazuh yet.
