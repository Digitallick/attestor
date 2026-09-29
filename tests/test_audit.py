import json

import pytest
from helpers import CASES, FIXED_NOW

from attestor import check_case, load_case
from attestor.audit import GENESIS, append_record, verify_chain
from attestor.errors import AuditError


@pytest.fixture
def report():
    return check_case(load_case(CASES / "bad_memo.json"), now=FIXED_NOW)


def write_three(path, report):
    return [append_record(path, report) for _ in range(3)]


def test_append_and_verify(tmp_path, report):
    path = tmp_path / "nested" / "audit.jsonl"
    records = write_three(path, report)
    assert [r["seq"] for r in records] == [1, 2, 3]
    assert records[0]["prev_hash"] == GENESIS
    assert records[1]["prev_hash"] == records[0]["hash"]
    status = verify_chain(path)
    assert status.ok and status.records == 3


def test_record_contains_no_pii(tmp_path, report):
    path = tmp_path / "audit.jsonl"
    append_record(path, report)
    text = path.read_text()
    assert "123-45-6789" not in text and "jane.doe" not in text


def test_edited_record_detected(tmp_path, report):
    path = tmp_path / "audit.jsonl"
    write_three(path, report)
    lines = path.read_text().splitlines()
    record = json.loads(lines[1])
    record["verdict"] = "PASS"
    lines[1] = json.dumps(record, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    status = verify_chain(path)
    assert not status.ok and status.broken_at == 2 and "hash" in status.reason


def test_deleted_record_detected(tmp_path, report):
    path = tmp_path / "audit.jsonl"
    write_three(path, report)
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    status = verify_chain(path)
    assert not status.ok and status.broken_at == 2


def test_blank_lines_ignored(tmp_path, report):
    path = tmp_path / "audit.jsonl"
    write_three(path, report)
    path.write_text(path.read_text().replace("\n", "\n\n"))
    assert verify_chain(path).ok


def test_missing_log(tmp_path):
    with pytest.raises(AuditError):
        verify_chain(tmp_path / "none.jsonl")
