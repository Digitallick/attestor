"""Append-only audit log. Each record carries the hash of the one before it."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from attestor.errors import AuditError
from attestor.models import Report, canonical_json

GENESIS = "0" * 64


@dataclass(frozen=True)
class ChainStatus:
    ok: bool
    records: int
    broken_at: int | None = None
    reason: str = ""


def _digest(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(record)).hexdigest()


def _lines(path: Path) -> list[str]:
    try:
        return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError as exc:
        raise AuditError(f"{path}: {exc.strerror or exc}") from exc


def append_record(path: str | Path, report: Report) -> dict[str, Any]:
    path = Path(path)
    lines = _lines(path) if path.exists() else []
    if lines:
        try:
            last = json.loads(lines[-1])
            seq, prev = int(last["seq"]), str(last["hash"])
        except (ValueError, KeyError, TypeError) as exc:
            raise AuditError(f"{path}: last record is unreadable; run verify-log") from exc
    else:
        seq, prev = 0, GENESIS

    counts = Counter(f.severity.value for f in report.findings)
    record = {
        "seq": seq + 1,
        "timestamp": report.timestamp,
        "case_id": report.case_id,
        "case_sha256": report.case_sha256,
        "policy_sha256": report.policy_sha256,
        "pack": report.pack,
        "verdict": report.verdict.value,
        "findings": {level: counts.get(level, 0) for level in ("block", "warn", "info")},
        "checks_failed": sorted({f.check_id for f in report.findings}),
        "judge_calls": len(report.judge_calls),
        "attestor_version": report.attestor_version,
        "prev_hash": prev,
    }
    record["hash"] = _digest(record)

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError as exc:
        raise AuditError(f"{path}: cannot write audit log ({exc.strerror or exc})") from exc
    return record


def verify_chain(path: str | Path) -> ChainStatus:
    path = Path(path)
    if not path.exists():
        raise AuditError(f"{path}: no audit log found")

    prev, count = GENESIS, 0
    for count, line in enumerate(_lines(path), start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return ChainStatus(False, count - 1, count, "record is not valid JSON")
        if not isinstance(record, dict):
            return ChainStatus(False, count - 1, count, "record is not a JSON object")
        claimed = record.pop("hash", None)
        if record.get("seq") != count:
            return ChainStatus(False, count - 1, count,
                               f"expected seq {count}, found {record.get('seq')}")
        if record.get("prev_hash") != prev:
            return ChainStatus(False, count - 1, count,
                               "prev_hash does not match the previous record")
        if claimed != _digest(record):
            return ChainStatus(False, count - 1, count, "hash does not match record contents")
        prev = claimed
    return ChainStatus(True, count)
