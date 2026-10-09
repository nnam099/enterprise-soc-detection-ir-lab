#!/usr/bin/env python3
"""Verify archived Windows PowerShell detection test evidence.

This verifies saved results, NOT current Wazuh rule execution.
"""

import base64
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "detections/wazuh/tests/encoded-powershell"

EXPECTED = {
    "T01": ("92057", 12),
    "T02": ("100504", 8),
    "T03": ("100504", 8),
    "T04": ("92027", 4),
}
ENCODED_RULES = {"100504", "92057"}


def load_json(path):
    with path.open(encoding="utf-8-sig") as stream:
        return json.load(stream)


def event_data(record):
    return (
        (record.get("data") or {})
        .get("win", {})
        .get("eventdata", {})
    )


def is_target_event(record, pid):
    agent = record.get("agent") or {}
    system = (
        (record.get("data") or {})
        .get("win", {})
        .get("system", {})
    )
    data = event_data(record)

    return (
        str(agent.get("id")) == "001"
        and str(system.get("eventID")) == "1"
        and str(data.get("processId")) == str(pid)
    )


def contains_marker(command, marker):
    if marker in command:
        return True

    match = re.search(
        r"(?i)(?:-|/)(?:EncodedCommand|enc)\s+([A-Za-z0-9+/=]+)",
        command,
    )

    if not match:
        return False

    try:
        payload = base64.b64decode(
            match.group(1), validate=True
        ).decode("utf-16le")
    except (ValueError, UnicodeError):
        return False

    return marker in payload


def check_test(test_id):
    execution = load_json(BASE / f"{test_id}-execution.json")
    alerts = load_json(BASE / test_id / f"{test_id}-alerts.json")
    archives = load_json(BASE / test_id / f"{test_id}-archives.json")

    if not isinstance(alerts, list) or not isinstance(archives, list):
        raise ValueError("Alerts and archives must be JSON arrays")

    pid = execution["ChildPID"]
    marker = execution["Marker"]
    expected_rule, expected_level = EXPECTED[test_id]

    if (
        str(execution.get("ExpectedRule")) != expected_rule
        and test_id != "T04"
    ):
        raise ValueError("Execution metadata disagrees with test plan")

    if (
        test_id != "T04"
        and execution.get("ExpectedLevel") != expected_level
    ):
        raise ValueError("Expected level disagrees with test plan")

    target_alerts = [
        record for record in alerts
        if is_target_event(record, pid)
    ]
    target_archives = [
        record for record in archives
        if is_target_event(record, pid)
    ]

    def correct_alert(record):
        rule = record.get("rule") or {}
        return (
            str(rule.get("id")) == expected_rule
            and rule.get("level") == expected_level
        )

    rule_ok = (
        bool(target_alerts)
        and any(correct_alert(x) for x in target_alerts)
    )

    if test_id == "T04":
        rule_ok = rule_ok and all(
            str((x.get("rule") or {}).get("id")) not in ENCODED_RULES
            for x in target_alerts
        )

    marker_in_alert = any(
        contains_marker(
            str(event_data(x).get("commandLine") or ""),
            marker,
        )
        for x in target_alerts
    )

    marker_in_archive = any(
        contains_marker(
            str(event_data(x).get("commandLine") or ""),
            marker,
        )
        for x in target_archives
    )

    passed = (
        rule_ok
        and marker_in_alert
        and marker_in_archive
        and bool(target_archives)
    )

    print(
        f"{test_id}: {'PASS' if passed else 'FAIL'} "
        f"rule={rule_ok} "
        f"alert_marker={marker_in_alert} "
        f"archive_marker={marker_in_archive} "
        f"alerts={len(target_alerts)} "
        f"archives={len(target_archives)}"
    )

    return passed


def main():
    results = []

    for test_id in EXPECTED:
        try:
            results.append(check_test(test_id))
        except (OSError, ValueError, TypeError, KeyError) as exc:
            print(f"{test_id}: ERROR — {exc}")
            results.append(False)

    passed = sum(results)

    print(f"\nARCHIVED EVIDENCE REGRESSION: {passed}/4 PASS")
    print("Scope: archived evidence verification only.")

    return 0 if passed == len(EXPECTED) else 1


if __name__ == "__main__":
    sys.exit(main())
