#!/usr/bin/env python3
"""UDP syslog relay: OPNsense (10.0.0.1) -> host (10.0.0.254:5514) -> Wazuh.

Run on the Parrot host. No root required because the port is > 1024.
"""

import socket

LISTEN = ("0.0.0.0", 5514)
WAZUH = ("192.168.50.30", 5514)

listen = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listen.bind(LISTEN)
send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print(f"relay listening on {LISTEN[0]}:{LISTEN[1]} -> {WAZUH[0]}:{WAZUH[1]}", flush=True)

while True:
    data, addr = listen.recvfrom(65535)
    print(f"{addr[0]}:{addr[1]} {data[:200]!r}", flush=True)
    send.sendto(data, WAZUH)
