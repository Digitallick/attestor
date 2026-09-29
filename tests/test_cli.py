import json

import pytest
from helpers import CASES
from typer.testing import CliRunner

from attestor.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def in_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def run(*args):
    # A narrow terminal, so long lines would wrap if the CLI let them.
    return runner.invoke(app, [str(a) for a in args], env={"COLUMNS": "60"})


def test_bad_memo_exits_1_and_writes_audit(in_tmp):
    result = run("check", CASES / "bad_memo.json")
    assert result.exit_code == 1
    assert "BLOCK" in result.output
    assert (in_tmp / ".attestor" / "audit.jsonl").exists()


def test_good_memo_exits_0():
    result = run("check", CASES / "good_memo.json", "--no-audit")
    assert result.exit_code == 0
    assert "PASS" in result.output


def test_json_output_masks_pii():
    result = run("check", CASES / "bad_memo.json", "--json", "--no-audit")
    data = json.loads(result.stdout)
    assert data["verdict"] == "BLOCK"
    assert "123-45-6789" not in result.stdout


def test_multiple_cases_json_list():
    result = run("check", CASES / "good_memo.json", CASES / "bad_memo.json", "--json", "--no-audit")
    assert [r["verdict"] for r in json.loads(result.stdout)] == ["PASS", "BLOCK"]


def test_strict_turns_warn_into_exit_2():
    assert run("check", CASES / "borderline.json", "--no-audit").exit_code == 0
    assert run("check", CASES / "borderline.json", "--no-audit", "--strict").exit_code == 2


def test_invalid_case_exit_3(in_tmp):
    bad = in_tmp / "bad.json"
    bad.write_text("{")
    result = run("check", bad)
    assert result.exit_code == 3
    assert "could not parse" in result.output
    assert "Traceback" not in result.output


def test_invalid_policy_exit_3(in_tmp):
    policy = in_tmp / "p.yaml"
    policy.write_text("checks:\n  nope: {}\n")
    result = run("check", CASES / "good_memo.json", "-p", policy)
    assert result.exit_code == 3
    assert "unknown check" in result.output


def test_verify_log_roundtrip():
    run("check", CASES / "good_memo.json")
    run("check", CASES / "bad_memo.json")
    result = run("verify-log")
    assert result.exit_code == 0
    assert "2 records" in result.output


def test_verify_log_missing_file():
    assert run("verify-log").exit_code == 3


def test_init_and_policy_pickup(in_tmp):
    assert run("init", "--pack", "general").exit_code == 0
    assert "pack: general" in (in_tmp / "attestor.yaml").read_text()
    assert run("init").exit_code == 3
    # general pack has no disclaimer rules, so an empty answer passes
    empty = in_tmp / "e.json"
    empty.write_text('{"answer": ""}')
    assert run("check", empty, "--strict", "--no-audit").exit_code == 0


def test_list_commands():
    out = run("list-checks").output
    for check_id in ("citation_grounding", "pii_leak", "prohibited_language"):
        assert check_id in out
    assert "finance" in run("list-packs").output
