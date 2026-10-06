#!/usr/bin/env python3
import argparse
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime

LOLBINS = {
    "powershell.exe","pwsh.exe","cmd.exe","rundll32.exe","regsvr32.exe",
    "mshta.exe","certutil.exe","bitsadmin.exe","wmic.exe","wscript.exe",
    "cscript.exe","schtasks.exe","sc.exe","installutil.exe","msbuild.exe"
}
OFFICE = {"winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","msaccess.exe"}
BROWSERS = {"chrome.exe","msedge.exe","firefox.exe","iexplore.exe","brave.exe"}
SERVICES = {"services.exe","svchost.exe","taskhostw.exe"}

ENC_RE = re.compile(r'(?i)(?:^|\s)-(?:enc|encodedcommand)\b')
URL_RE = re.compile(r'(?i)\bhttps?:\/\/[^\s"\']+')
IP_RE = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
B64_RE = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])')

def get(d, *keys, default=""):
    cur = d
    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur if cur is not None else default

def s(v):
    return "" if v is None else str(v)

def basename_win(path):
    return s(path).replace("/", "\\").rsplit("\\", 1)[-1].lower()

def path_depth(path):
    p = s(path).replace("/", "\\").strip("\\")
    return 0 if not p else p.count("\\") + 1

def is_user_writable(path):
    x = s(path).lower().replace("/", "\\")
    needles = ["\\users\\", "\\appdata\\", "\\temp\\", "\\downloads\\", "\\desktop\\", "\\programdata\\"]
    return int(any(n in x for n in needles))

def is_external_ip(value):
    try:
        ip = ipaddress.ip_address(s(value).strip())
        return int(not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved))
    except ValueError:
        return 0

def port_category(value):
    try:
        p = int(value)
    except (TypeError, ValueError):
        return "none"
    if p <= 0:
        return "none"
    if p <= 1023:
        return "well_known"
    if p <= 49151:
        return "registered"
    return "dynamic"

def parse_ts(ts):
    try:
        dt = datetime.strptime(s(ts), "%Y-%m-%dT%H:%M:%S.%f%z")
        return dt.hour, dt.weekday()
    except ValueError:
        return -1, -1

def first(ed, *names):
    for name in names:
        if name in ed and ed[name] not in (None, ""):
            return s(ed[name])
    return ""

def normalize(obj):
    win = get(obj, "data", "win", default={})
    system = win.get("system", {}) if isinstance(win, dict) else {}
    ed = win.get("eventdata", {}) if isinstance(win, dict) else {}
    if not isinstance(system, dict):
        system = {}
    if not isinstance(ed, dict):
        ed = {}

    image = first(ed, "image", "Image")
    parent_image = first(ed, "parentImage", "ParentImage")
    command_line = first(ed, "commandLine", "CommandLine")
    parent_command_line = first(ed, "parentCommandLine", "ParentCommandLine")
    user = first(ed, "user", "User", "subjectUserName", "targetUserName")
    integrity = first(ed, "integrityLevel", "IntegrityLevel")
    dest_ip = first(ed, "destinationIp", "DestinationIp", "destIp")
    dest_port = first(ed, "destinationPort", "DestinationPort", "destPort")
    protocol = first(ed, "protocol", "Protocol")
    target_filename = first(ed, "targetFilename", "TargetFilename")
    registry_target = first(ed, "targetObject", "TargetObject")
    registry_details = first(ed, "details", "Details")
    query_name = first(ed, "queryName", "QueryName")
    process_guid = first(ed, "processGuid", "ProcessGuid")
    parent_process_guid = first(ed, "parentProcessGuid", "ParentProcessGuid")

    image_name = basename_win(image)
    parent_name = basename_win(parent_image)
    hour, dow = parse_ts(obj.get("timestamp", ""))
    cl = command_line

    return {
        "timestamp": s(obj.get("timestamp", "")),
        "agent_id": s(get(obj, "agent", "id")),
        "agent_name": s(get(obj, "agent", "name")),
        "agent_ip": s(get(obj, "agent", "ip")),
        "channel": s(system.get("channel", "")),
        "provider": s(system.get("providerName", "")),
        "event_id": s(system.get("eventID", "")),
        "computer": s(system.get("computer", "")),
        "image": image,
        "image_name": image_name,
        "parent_image": parent_image,
        "parent_image_name": parent_name,
        "command_line": command_line,
        "parent_command_line": parent_command_line,
        "user": user,
        "integrity_level": integrity,
        "destination_ip": dest_ip,
        "destination_port": dest_port,
        "protocol": protocol,
        "target_filename": target_filename,
        "registry_target_object": registry_target,
        "registry_details": registry_details,
        "dns_query_name": query_name,
        "process_guid": process_guid,
        "parent_process_guid": parent_process_guid,
        "hour": hour,
        "day_of_week": dow,
        "is_powershell": int(image_name in {"powershell.exe", "pwsh.exe"}),
        "is_cmd": int(image_name == "cmd.exe"),
        "is_lolbin": int(image_name in LOLBINS),
        "is_system32": int("\\windows\\system32\\" in image.lower().replace("/", "\\")),
        "is_user_writable_path": is_user_writable(image),
        "has_encoded_command": int(bool(ENC_RE.search(cl))),
        "has_url": int(bool(URL_RE.search(cl))),
        "has_ip_address": int(bool(IP_RE.search(cl))),
        "has_base64_like_string": int(bool(B64_RE.search(cl))),
        "parent_is_office": int(parent_name in OFFICE),
        "parent_is_browser": int(parent_name in BROWSERS),
        "parent_is_service": int(parent_name in SERVICES),
        "is_external_ip": is_external_ip(dest_ip),
        "destination_port_category": port_category(dest_port),
        "command_length": len(cl),
        "path_depth": path_depth(image),
        "rule_id": s(get(obj, "rule", "id")),
        "rule_level": s(get(obj, "rule", "level")),
        "rule_description": s(get(obj, "rule", "description")),
    }

def main():
    parser = argparse.ArgumentParser(description="Normalize Wazuh Windows JSONL into SOC-LAB schema v2.")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--report")
    args = parser.parse_args()

    total = written = malformed = 0
    event_counts = Counter()
    channel_counts = Counter()

    with open(args.input, "r", encoding="utf-8") as src, open(args.output, "w", encoding="utf-8") as dst:
        for line in src:
            total += 1
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue

            row = normalize(obj)
            if not row["channel"]:
                continue

            dst.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            written += 1
            event_counts[row["event_id"]] += 1
            channel_counts[row["channel"]] += 1

    report = {
        "input_lines": total,
        "written_events": written,
        "malformed_lines": malformed,
        "top_event_ids": event_counts.most_common(20),
        "channels": channel_counts.most_common(),
    }

    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

    print(json.dumps(report, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
