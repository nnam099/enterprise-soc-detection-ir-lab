#!/usr/bin/env python3

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

CASE_ID = "DFIR-001"

TIMELINE_JSONL = (
    ROOT
    / "dfir"
    / "timelines"
    / f"{CASE_ID}-timeline.jsonl"
)

TIMELINE_CSV = (
    ROOT
    / "dfir"
    / "timelines"
    / f"{CASE_ID}-timeline.csv"
)

TIMELINE_MD = (
    ROOT
    / "dfir"
    / "timelines"
    / f"{CASE_ID}-timeline.md"
)

HASH_FILE = (
    ROOT
    / "dfir"
    / "evidence"
    / CASE_ID
    / "SHA256SUMS.txt"
)

SCHEMA_FILE = (
    ROOT
    / "dfir"
    / "schemas"
    / "timeline-schema.json"
)

REQUIRED_FILES = [
    TIMELINE_JSONL,
    TIMELINE_CSV,
    TIMELINE_MD,
    HASH_FILE,
    SCHEMA_FILE,
]


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b""
        ):
            digest.update(chunk)

    return digest.hexdigest()


def check_required_files():
    print("[+] Checking required files")

    ok = True

    for path in REQUIRED_FILES:
        if path.exists():
            print(
                f"    [OK] {path.relative_to(ROOT)}"
            )
        else:
            print(
                f"    [MISSING] {path.relative_to(ROOT)}"
            )
            ok = False

    return ok


def load_hash_manifest():
    hashes = {}

    if not HASH_FILE.exists():
        return hashes

    for line in HASH_FILE.read_text(
        encoding="utf-8"
    ).splitlines():

        line = line.strip()

        if not line:
            continue

        parts = line.split(
            None,
            1
        )

        if len(parts) != 2:
            continue

        digest, filename = parts

        hashes[filename.strip()] = digest.strip()

    return hashes


def verify_hashes():
    print("[+] Verifying SHA-256 evidence integrity")

    expected = load_hash_manifest()

    if not expected:
        print("    [FAIL] Hash manifest is empty")
        return False

    ok = True

    for filename, expected_hash in expected.items():

        path = ROOT / filename

        if not path.exists():
            print(
                f"    [MISSING] {filename}"
            )
            ok = False
            continue

        actual_hash = sha256_file(
            path
        )

        if actual_hash == expected_hash:
            print(
                f"    [OK] {filename}"
            )

        else:
            print(
                f"    [FAIL] {filename}"
            )

            print(
                f"           expected: {expected_hash}"
            )

            print(
                f"           actual:   {actual_hash}"
            )

            ok = False

    return ok


def check_jsonl():
    print("[+] Checking JSONL timeline")

    if not TIMELINE_JSONL.exists():
        print("    [FAIL] Timeline missing")
        return False

    count = 0
    ok = True

    with TIMELINE_JSONL.open(
        "r",
        encoding="utf-8"
    ) as f:

        for line_number, line in enumerate(
            f,
            start=1
        ):

            line = line.strip()

            if not line:
                continue

            try:
                obj = json.loads(
                    line
                )

            except json.JSONDecodeError as exc:
                print(
                    f"    [FAIL] Invalid JSON line "
                    f"{line_number}: {exc}"
                )

                ok = False
                continue

            if not isinstance(
                obj,
                dict
            ):
                print(
                    f"    [FAIL] Line {line_number} "
                    f"is not a JSON object"
                )

                ok = False
                continue

            required = [
                "timestamp",
                "hunt_id",
                "source_file",
                "source_type",
                "event_category",
            ]

            missing = [
                field
                for field in required
                if field not in obj
            ]

            if missing:
                print(
                    f"    [FAIL] Line {line_number} "
                    f"missing: {', '.join(missing)}"
                )

                ok = False
                continue

            count += 1

    print(
        f"    [+] Valid timeline records: {count}"
    )

    if count == 0:
        ok = False

    return ok


def check_source_types():
    print("[+] Checking evidence source types")

    allowed = {
        "raw_telemetry",
        "wazuh_alert",
    }

    observed = set()

    with TIMELINE_JSONL.open(
        "r",
        encoding="utf-8"
    ) as f:

        for line in f:
            line = line.strip()

            if not line:
                continue

            obj = json.loads(
                line
            )

            source_type = obj.get(
                "source_type"
            )

            observed.add(
                source_type
            )

    unknown = (
        observed - allowed
    )

    if unknown:
        print(
            f"    [FAIL] Unknown source types: {unknown}"
        )

        return False

    for source_type in sorted(
        observed
    ):
        print(
            f"    [OK] {source_type}"
        )

    return True


def main():
    print(
        f"=== {CASE_ID} Verification ==="
    )

    results = {
        "required_files": check_required_files(),
        "hash_integrity": verify_hashes(),
        "jsonl_validity": check_jsonl(),
        "source_types": check_source_types(),
    }

    print("")
    print("[+] Verification summary")

    overall = True

    for name, result in results.items():
        state = (
            "PASS"
            if result
            else "FAIL"
        )

        print(
            f"    {name}: {state}"
        )

        if not result:
            overall = False

    print("")

    if overall:
        print(
            f"[PASS] {CASE_ID} evidence pipeline verified"
        )

        return 0

    print(
        f"[FAIL] {CASE_ID} verification failed"
    )

    return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
