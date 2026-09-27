# SOC Lab IP Plan

| Node | IP | Role | DNS |
|---|---:|---|---|
| Parrot/libvirt gateway | 192.168.50.1 | NAT gateway for SOC lab | - |
| SOC-DC01 | 192.168.50.10 | Windows Server 2022 AD DS + DNS | 192.168.50.10 |
| SOC-WIN10 | 192.168.50.20 | Windows 10 endpoint | 192.168.50.10 when domain is active |
| SOC-WAZUH | 192.168.50.30 | Wazuh single-node SIEM | 1.1.1.1 or gateway DNS |
| DHCP pool | 192.168.50.100-200 | Temporary lab VMs | gateway/libvirt DNS |
