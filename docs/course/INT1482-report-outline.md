# Khung báo cáo An toàn mạng (INT1482)

**Sinh viên:** Võ Nguyễn Nhật Nam
**Môn học:** An toàn mạng — INT1482
**Đề tài đề xuất:** Xây dựng lab an toàn mạng doanh nghiệp: Active Directory, SIEM và firewall/IDS

> Đây là khung báo cáo, không phải bản nộp cuối. Các mục đánh dấu `[CẦN ĐIỀN]` phải được hoàn thiện và kiểm chứng trước khi nộp.

---

## 1. Mở đầu

- Lý do chọn đề tài: kết hợp giám sát SOC với kiểm thử an toàn mạng trong môi trường cô lập.
- Mục tiêu:
  1. Xây dựng AD domain + endpoint + SIEM.
  2. Mô phỏng tấn công mạng có kiểm soát (recon/scan).
  3. Phát hiện, ngăn chặn và ứng cứu.
  4. Đánh giá hiệu quả của firewall/IDS.
- Phạm vi: lab nội bộ trên KVM/QEMU, 8 GB RAM, tối đa 2 VM đồng thời.
- Giới hạn: không tấn công hệ thống ngoài lab; không dùng dữ liệu thật.

## 2. Cơ sở lý thuyết (Ch1–Ch2)

Tóm tắt ngắn, chỉ giữ phần liên quan đến lab:

- Mô hình phòng thủ nhiều lớp, nguyên tắc least privilege.
- Lỗ hổng giao thức: SMB, Kerberos, LDAP, WinRM, FTP, SSH.
- Vai trò firewall, DMZ, IDS/IPS, segmentation.
- Quy trình ứng cứu: phát hiện → phân tích → containment → recovery.

## 3. Kiến trúc lab

### 3.1 SOC Mode

| Thành phần | IP | Vai trò |
|---|---|---|
| SOC-DC01 / DC01 | 192.168.50.10 | AD DS, DNS, Kerberos, LDAP |
| SOC-WIN10 | 192.168.50.20 | Endpoint, Sysmon, Wazuh Agent 001 |
| SOC-WAZUH | 192.168.50.30 | Manager, Indexer, Dashboard |

- Sơ đồ: [`architecture/topology.md`](../../architecture/topology.md)
- IP plan: [`architecture/ip-plan.md`](../../architecture/ip-plan.md)
- Xác minh kết nối: [`evidence/lab-connectivity/lab-connectivity-20261026.md`](../../evidence/lab-connectivity/lab-connectivity-20261026.md)

### 3.2 Network Security Mode

| Thành phần | IP | Vai trò |
|---|---|---|
| OPNsense 26.7 | WAN 192.168.50.1 · LAN 10.0.0.1 | Firewall |
| Metasploitable 2 | 10.0.0.5 | Target |
| Attacker-MSF (tạm) | 192.168.50.10 | Attacker WAN-side |
| Parrot host | 10.0.0.254 | Kiểm thử LAN-side |

- Chi tiết: [`architecture/network-security-mode.md`](../../architecture/network-security-mode.md)
- Ảnh: `screenshots/phase7-network/`

## 4. Triển khai

### 4.1 Domain & endpoint

- Tạo domain `SOC-LAB.LOCAL`, join WIN10, bật Sysmon và audit policy.
- `[CẦN ĐIỀN]` ảnh/cấu hình thực tế: domain join, Sysmon config, audit policy.

### 4.2 SIEM & detection

- Wazuh 4.14.8, agent 001/002.
- Rule custom: 100501–100507 (registry, WinRM, auth, PowerShell, AD enumeration).
- Bằng chứng: `detections/`, `ad-labs/`, `hunting/`.

### 4.3 Firewall & target

- OPNsense: WAN/LAN, DHCP reservation cho target.
- Kết quả:
  - LAN → target: 21/22/80 **open**.
  - WAN → target: 21/22/80 **filtered**.
  - PCAP: `evidence/network-lab/pcap/wan-scan-20261026.pcap`.

## 5. Kịch bản tấn công (Ch3)

### 5.1 Recon / scan

- `nmap -PN -sT -p 21,22,80 10.0.0.5` từ WAN → filtered.
- `nmap -sV` từ LAN → vsftpd 2.3.4, OpenSSH 4.7p1, Apache 2.2.8.
- Nhận xét: firewall chặn truy cập trực tiếp; target vẫn lộ dịch vụ khi đứng trong LAN.

### 5.2 Khai thác — đã hoàn thành

- CVE-2011-2523: backdoor vsftpd 2.3.4.
- Thực hiện từ **Parrot host** `10.0.0.254` trong `Vung_LAN`.
- Kết quả: `uid=0(root)`, hostname `metasploitable`.
- Bằng chứng: [`exploit-vsftpd-20261026.md`](../../evidence/network-lab/exploit-vsftpd-20261026.md)
- Nhận xét: firewall chặn từ WAN nhưng không bảo vệ khi attacker đã ở trong LAN → cần segmentation, IDS/EDR và vá lỗi.

### 5.3 DoS — đã hoàn thành (mức ứng dụng)

- Công cụ: ApacheBench từ Parrot host `10.0.0.254`.
- Kịch bản: 200 request đồng thời trong 10 giây vào Apache `10.0.0.5`.
- Kết quả: thời gian phản hồi tăng từ **58 ms → 1.143 ms (~20 lần)**, không có request lỗi; phục hồi ngay sau khi dừng.
- Bằng chứng: [`dos-http-20261026.md`](../../evidence/network-lab/dos-http-20261026.md)
- Hạn chế: không dùng được SYN flood (`hping3` cần root); chưa có IDS. Hướng tiếp theo: slowloris/rate-limit.

## 6. Phát hiện & ứng cứu (Ch4)

- Wazuh alert: encoded PowerShell, WinRM, failed logon, registry persistence.
- Quy trình containment/recovery: `incidents/INC-003`, `incidents/SOC-INC-001`.
- `[CẦN ĐIỀN]` alert IDS Suricata + log OPNsense → Wazuh (nếu bật).

## 7. Đánh giá

| Tiêu chí | Kết quả |
|---|---|
| Firewall chặn recon từ WAN | Đạt (PCAP) |
| Phát hiện hành vi trên endpoint | Đạt (Wazuh) |
| Ứng cứu & khôi phục | Đạt (INC-003) |
| IDS/IPS | Chưa |
| Khai thác & DoS | Khai thác: Đạt (LAN, vsftpd root shell) · DoS: Đạt (HTTP load, ~20× latency) |
| Độ tái lập | Cao (script + evidence) |

## 8. Hạn chế

- 8 GB RAM, tối đa 2 VM → không chạy đồng thời toàn bộ hệ thống.
- Attacker WAN-side hiện là clone Metasploitable; khai thác LAN dùng Parrot host.
- DoS mới ở mức ứng dụng (HTTP load), chưa có SYN flood/slowloris do giới hạn quyền.
- Chưa có Suricata/IDS và chưa gửi log mạng về Wazuh.
- Một số bằng chứng cũ (Lab6) không tái lập được trước khi sửa mạng.

## 9. Kết luận & hướng phát triển

- Lab chứng minh được vòng đời: tấn công → phát hiện → ứng cứu.
- Hướng tiếp theo: Kali + Suricata + syslog Wazuh + báo cáo định lượng.

## 10. Phụ lục

- Danh sách script: `automation/`, `attacks/wan-recon/`.
- Danh sách bằng chứng và SHA-256: `evidence/`.
- Câu lệnh tái lập: xem README từng thư mục.

---

## Ghi chú khi nộp

1. Chạy lại `./automation/lab-connectivity-check.sh` và lưu output.
2. Chạy `./automation/network-lab-check.sh` khi bật Network Mode.
3. Không đưa mật khẩu, private key, hoặc IP public vào báo cáo.
4. Nêu rõ đây là môi trường lab cô lập, có sự cho phép.
