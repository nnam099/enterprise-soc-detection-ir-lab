# OPNsense Admin Password Recovery — Status

**Date:** 2026-10-26
**Status:** **RESOLVED (2026-10-26)** — admin password reset offline; OPNsense boots, web login verified, firewall and IDS validated.

> The new password is not stored in this repository. It was shared with the lab owner and should be changed after the lab work.

---

## Resolution

The reset was performed on a **copy** of the OPNsense disk:

1. Backed up the original: `/home/nnam09/VM/lab/OPNsense-Lab6-backup-20261026.qcow2`.
2. Connected the copy via `qemu-nbd` and located the bcrypt hash in `config.xml` (5 copies, including backups).
3. Replaced the 60-byte hash in place at the exact raw offsets — Linux UFS write support was unavailable, so no filesystem mount was needed.
4. Booted `OPNsense-ResetTest` from the edited copy and verified `Dashboard | Lobby` login over HTTPS.
5. Applied the verified copy to `/var/lib/libvirt/images/OPNsense-Lab6.qcow2` and re-verified login on the main VM.

This preserved the WAN/LAN/DHCP configuration and avoided a reinstall.

---

## What Is Known

| Item | Status |
|---|---|
| OPNsense version | 26.7 (amd64) |
| Console login | `root` prompt reachable; password unknown |
| Default `root` / `opnsense` | Tested once → `Login incorrect` |
| Web UI | Not accessible without credentials |
| Firewall function | Normal (WAN `192.168.50.1`, LAN `10.0.0.1`) |
| Impact | Suricata/IDS, syslog export and web UI changes are blocked |

---

## What Was Tried

1. Serial console (`virsh console`) — no guest output; OPNsense uses the video console.
2. FreeBSD loader prompt (`boot -s`) — failed with `No boot on 0:ad(0p3)`.
3. Direct kernel load (`boot /boot/kernel/kernel -s`) — `BTX halted`.
4. Normal reboot after the failed attempts — **OPNsense booted normally**, so the disk/config was not damaged.

> Do not repeat loader/single-user attempts without a recovery plan; the loader path on this image is fragile.

---

## Safe Recovery Options

### Option A — Reinstall OPNsense (recommended)

The current OPNsense configuration is minimal and documented:

- WAN `192.168.50.1/24`
- LAN `10.0.0.1/24`
- DHCP on LAN is not required (the target uses a libvirt reservation)

Steps:

1. Download the OPNsense 26.7 DVD/ISO.
2. Attach it as a CD-ROM to `OPNsense-Lab6`.
3. Boot the installer, install to the existing disk (this erases the OPNsense config only).
4. Assign `vtnet0` = LAN, `vtnet1` = WAN.
5. Set LAN `10.0.0.1/24`, WAN `192.168.50.1/24`.
6. Re-run `./automation/network-lab-check.sh`.

Estimated time: 20–30 minutes. No VM disk images other than OPNsense are affected.

### Option B — Offline edit with sudo (preserves config)

Requires the host sudo password and comfort with UFS:

```sh
sudo modprobe nbd max_part=8
sudo qemu-nbd -c /dev/nbd0 /var/lib/libvirt/images/OPNsense-Lab6.qcow2
sudo partprobe /dev/nbd0
sudo mount -t ufs -o ufstype=ufs2,ro /dev/nbd0p3 /mnt
# inspect /mnt/conf/config.xml and /mnt/etc/master.passwd
sudo umount /mnt
sudo qemu-nbd -d /dev/nbd0
```

Editing `master.passwd` / `config.xml` requires generating a compatible bcrypt hash and preserving file offsets; test on a copy first. This is higher risk than reinstalling.

### Option C — Leave IDS disabled

The course evidence already covers:

- firewall filtering from WAN (PCAP)
- internal exploitation (root shell)
- DoS/availability degradation

Suricata/IDS is a bonus, not a blocker for the current deliverables.

---

## Recommendation

If IDS is required for the report, reinstall OPNsense (Option A) — it is faster and safer than offline surgery. If the config must be preserved, use Option B on a **copy** of the disk first.
