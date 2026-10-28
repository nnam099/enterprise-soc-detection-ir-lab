# Phân công công việc — Báo cáo An toàn mạng (INT1482)

**Nhóm sinh viên:**
- Võ Nguyễn Nhật Nam (MSSV: `[điền]`)
- Hồ Mạnh Danh (MSSV: `[điền]`)

**Môn học:** An toàn mạng — INT1482
**Đề tài:** Xây dựng lab an toàn mạng doanh nghiệp: Active Directory, SIEM và firewall/IDS

---

## 1. Nguyên tắc phân công

Lab được chia thành hai nhánh chính theo hướng tấn công / phòng thủ:

- **Võ Nguyễn Nhật Nam** — nhánh **phòng thủ & giám sát** (SOC / blue team): Active Directory, Wazuh SIEM, detection engineering, threat hunting, incident response, DFIR và mở rộng hybrid cloud.
- **Hồ Mạnh Danh** — nhánh **kiểm thử & an toàn mạng** (red team + firewall/IDS): cấu hình OPNsense, recon/scan, khai thác lỗ hổng, DoS, Suricata IDS và tích hợp log mạng vào SIEM.

Các công việc chung (thiết kế kiến trúc tổng thể, kiểm chứng kết nối, viết báo cáo) do cả hai thành viên cùng thực hiện.

---

## 2. Võ Nguyễn Nhật Nam — Nhánh phòng thủ & giám sát (SOC)

| STT | Nhiệm vụ | Kết quả | Bằng chứng |
|---|---|---|---|
| 1 | Xây dựng miền `SOC-LAB.LOCAL` (AD DS + DNS/Kerberos/LDAP) trên `SOC-DC01` | Hoàn thành — domain hoạt động, chức năng domain level 7 | `evidence/lab-connectivity/` |
| 2 | Triển khai Wazuh SIEM 4.14.8 (Manager + Indexer + Dashboard) trên `SOC-WAZUH` | Hoàn thành — dashboard/API/ingest hoạt động | `evidence/lab-connectivity/` |
| 3 | Cấu hình endpoint `SOC-WIN10` (join domain, Sysmon, audit policy) | Hoàn thành — agent 001 gửi telemetry | `configs/sysmon/`, `configs/windows-auditing/` |
| 4 | Phát triển custom detection rules 100501–100508 (ánh xạ MITRE ATT&CK) | Hoàn thành — 8 rule, có kiểm thử hồi quy | `configs/wazuh/rules/`, `detections/wazuh/rules/` |
| 5 | Threat hunting có giả thuyết HUNT-001 → HUNT-004 | Hoàn thành — 4 báo cáo hunting | `hunting/` |
| 6 | Incident response INC-003 và SOC-INC-001 (containment + recovery) | Hoàn thành — 3/3 regression, 7/7 SHA-256 | `incidents/` |
| 7 | DFIR DFIR-001 (timeline) và DFIR-002 (EVTX/Prefetch) | Hoàn thành — 261/261 SHA-256 | `dfir/` |
| 8 | Mở rộng Hybrid Cloud (Recommendation #1): EC2 + Tailscale + AWS logs → S3 → Wazuh, rule 100508 | Hoàn thành — agent 003, CloudTrail/Flow Logs, alert level 10 | `evidence/cloud/`, `detections/wazuh/rules/100508-aws-iam.xml` |

---

## 3. Hồ Mạnh Danh — Nhánh kiểm thử & an toàn mạng

| STT | Nhiệm vụ | Kết quả | Bằng chứng |
|---|---|---|---|
| 1 | Cấu hình OPNsense 26.7 (WAN/LAN, DMZ, DHCP reservation cho target) | Hoàn thành — WAN/LAN phân tách, target `.5` | `architecture/network-security-mode.md` |
| 2 | Recon & scan (nmap từ WAN và LAN) | Hoàn thành — WAN **filtered**, LAN **open** (21/22/80) | `evidence/network-lab/firewall-test-20261026.md` |
| 3 | Khai thác vsftpd 2.3.4 (CVE-2011-2523) | Hoàn thành — root shell trên Metasploitable | `evidence/network-lab/exploit-vsftpd-20261026.md` |
| 4 | DoS mức ứng dụng (ApacheBench HTTP load) | Hoàn thành — phản hồi 58 ms → 1.143 ms (~20 lần) | `evidence/network-lab/dos-http-20261026.md` |
| 5 | Triển khai Suricata 8.0.6 (IDS) + ET Open subset (3.469 rules) | Hoàn thành — bắt 10 alert cho scan WAN | `evidence/network-lab/ids-suricata-20261026.md` |
| 6 | Tích hợp log mạng → Wazuh (OPNsense syslog rule 100011, Suricata `eve.json` rule 86601) | Hoàn thành — syslog + 12 alert eve.json | `evidence/network-lab/syslog-integration-20261026.md`, `suricata-wazuh-20261026.md` |

---

## 4. Công việc chung (cả hai thành viên)

| STT | Nhiệm vụ | Kết quả |
|---|---|---|
| 1 | Thiết kế kiến trúc tổng thể (SOC + Network Security Mode, IP plan, resource modes) | Hoàn thành — `architecture/` |
| 2 | Kiểm chứng kết nối & sức khỏe hệ thống | Hoàn thành — 3/3 VM boot, script `automation/lab-connectivity-check.sh` |
| 3 | Viết báo cáo & tổng hợp bằng chứng SHA-256 | Đang thực hiện |

---

## 5. Tỷ lệ đóng góp ước tính

| Thành viên | Nhánh | Tỷ lệ |
|---|---|---|
| Võ Nguyễn Nhật Nam | Phòng thủ & giám sát (SOC + Cloud) | ~55% |
| Hồ Mạnh Danh | Kiểm thử & an toàn mạng (Firewall/IDS) | ~45% |

*Tỷ lệ là ước tính; chi tiết theo bảng phân công ở mục 2–4. Toàn bộ thao tác được thực hiện trong môi trường lab cô lập, có sự cho phép, không ảnh hưởng hệ thống ngoài lab.*
