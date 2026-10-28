# Kịch bản demo — Tấn công qua Active Directory (INT1482)

**Mục tiêu:** Mô phỏng chuỗi tấn công (kill chain) nhắm vào miền `SOC-LAB.LOCAL` và chứng minh
khả năng phát hiện của Wazuh SIEM qua các custom rule đã xây dựng.

**Kẻ tấn công:** Parrot host (`192.168.50.1`) hoặc endpoint `SOC-WIN10` (đã bị chiếm).
**Nạn nhân:** Domain Controller `SOC-DC01` (`192.168.50.10`).
**Giám sát:** `SOC-WAZUH` (`192.168.50.30`).

> Toàn bộ là mô phỏng có kiểm soát trong lab cô lập, có sự cho phép. Không tấn công hệ thống ngoài lab.

---

## Sơ đồ kill chain

```text
Recon (liệt kê AD) → Credential Access (dò mật khẩu) → Lateral Movement (WinRM)
      → Execution (PowerShell mã hóa) → Persistence (Run key)  →  Detection (Wazuh) → Response
```

| Bước | Kỹ thuật | Rule phát hiện | MITRE |
|---|---|---|---|
| 1 | AD Enumeration | 100506 | T1087.002 |
| 2 | Password spray / brute force | 100507 + 100503 | T1110 |
| 3 | WinRM lateral movement | 100502 | T1021.006 |
| 4 | Encoded PowerShell | 100504 | T1059.001 |
| 5 | Registry Run key persistence | 100501 | T1547.001 |

---

## Bước 0 — Chuẩn bị

Bật mode phù hợp (theo [`resource-modes.md`](../../architecture/resource-modes.md)), không quá 2 VM đồng thời:

| Phase | VM chạy | Nội dung demo |
|---|---|---|
| Phase A — Credential + Lateral | `SOC-DC01` + `SOC-WAZUH` | Bước 2, 3 (kẻ tấn công từ Parrot) |
| Phase B — Exec + Persist + Enum | `SOC-WIN10` + `SOC-WAZUH` | Bước 1, 4, 5 (kẻ tấn công trên WIN10) |

---

## Bước 1 — Recon: Liệt kê tài khoản/grupo trong AD

Mô phỏng kẻ tấn công thu thập thông tin user/group để chọn mục tiêu.

```powershell
# Chạy trên SOC-WIN10 (có RSAT) hoặc SOC-DC01
Get-ADUser -Filter * | Select-Object SamAccountName, Enabled
Get-ADGroupMember -Identity "Domain Admins" | Select-Object SamAccountName
```

- **Telemetry:** PowerShell Script Block Logging (EID 4104).
- **Phát hiện:** Rule **100506** — *SOC Lab: PowerShell Active Directory enumeration observed*.

---

## Bước 2 — Credential Access: Dò mật khẩu (password spray)

Mô phỏng kẻ tấn công thử sai mật khẩu nhiều lần vào một tài khoản để đoán mật khẩu.

```powershell
# Từ SOC-WIN10: 5 lần thử sai vào tài khoản test (trong 60 giây)
1..5 | ForEach-Object {
  net use \\dc01.soc-lab.local /user:soc-lab\soc.ad002.test "SaiMatKhau$_" 2>$null
}
```

- **Telemetry:** Windows Security 4625 (Logon Failure) trên `SOC-DC01`.
- **Phát hiện:**
  - Rule **100507** (level 3) — classifier lỗi sai mật khẩu (SubStatus `0xc000006a`).
  - Rule **100503** (level 10) — correlation 5 lần thất bại trong 60 giây cùng 1 tài khoản.

---

## Bước 3 — Lateral Movement: WinRM sang máy khác

Mô phỏng kẻ tấn công dùng WinRM để di chuyển ngang trong mạng.

```powershell
# Từ SOC-WIN10: kết nối WinRM tới DC01 (dùng tài khoản đã chiếm)
Enter-PSSession -ComputerName dc01.soc-lab.local -Credential (Get-Credential)
# hoặc
Invoke-Command -ComputerName dc01.soc-lab.local -ScriptBlock { whoami }
```

- **Telemetry:** Sysmon EID 1 (process `wsmprovhost.exe`) trên máy đích.
- **Phát hiện:** Rule **100502** — *WinRM process execution*.

---

## Bước 4 — Execution: PowerShell mã hóa

Mô phỏng kẻ tấn công chạy payload qua `-EncodedCommand` để né tránh kiểm tra.

```powershell
# Tạo payload (lành tính) rồi chạy mã hóa
$cmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Get-Date'))
powershell -EncodedCommand $cmd
```

- **Telemetry:** Sysmon EID 1 (dòng lệnh chứa `-EncodedCommand`).
- **Phát hiện:** Rule **100504** — *Encoded PowerShell command*.

---

## Bước 5 — Persistence: Registry Run key

Mô phỏng kẻ tấn công tạo cơ chế duy trì (tự chạy khi đăng nhập).

```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Updater" /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
```

- **Telemetry:** Sysmon EID 13 (Registry value set) trên `SOC-WIN10`.
- **Phát hiện:** Rule **100501** — *Registry Run Key modification*.

---

## Phát hiện & ứng cứu

1. **Triage** trong Wazuh dashboard: lọc theo rule 100501–100507, xác nhận chuỗi alert.
2. **Containment:**
   ```powershell
   # Dừng tiến trình độc hại (nếu có)
   Stop-Process -Id <PID> -Force
   # Vô hiệu tài khoản bị xâm nhập trên DC
   Disable-ADAccount -Identity soc.ad002.test
   ```
3. **Recovery & xác minh:** kiểm tra Run key đã xóa, tài khoản đã khóa, agent vẫn Active.

---

## Bằng chứng cần capture

| Bằng chứng | Cách capture |
|---|---|
| Alert Wazuh (từng rule) | Dashboard → filter rule id → chụp ảnh |
| Alert JSON thô | `grep <rule_id> /var/ossec/logs/alerts/alerts.json` |
| `agent_control -l` (agent Active) | `sudo /var/ossec/bin/agent_control -l` |
| SHA-256 manifest | `sha256sum <files> > SHA256SUMS.txt` |

---

*Kịch bản demo phục vụ báo cáo INT1482. Mọi thao tác trong lab cô lập, có sự cho phép, không ảnh hưởng hệ thống ngoài lab.*
