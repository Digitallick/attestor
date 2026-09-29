import json

import pytest

from attestor.errors import CaseError
from attestor.loader import load_case


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_json_case_and_defaults_id(tmp_path):
    path = write(tmp_path, "memo.json", json.dumps({
        "answer": "Hi.",
        "sources": [{"id": "S1", "text": "x"}],
    }))
    case = load_case(path)
    assert case.id == "memo"
    assert case.source("S1").text == "x"
    assert case.source("S2") is None


def test_loads_yaml_case(tmp_path):
    path = write(tmp_path, "c.yaml", "id: abc\nanswer: Hello.\nsources:\n  - id: S1\n    text: t\n")
    assert load_case(path).id == "abc"


def test_duplicate_source_ids_rejected(tmp_path):
    path = write(tmp_path, "c.json", json.dumps({
        "answer": "a",
        "sources": [{"id": "S1", "text": "x"}, {"id": "S1", "text": "y"}],
    }))
    with pytest.raises(CaseError, match="duplicate source id"):
        load_case(path)


def test_malformed_json(tmp_path):
    with pytest.raises(CaseError, match="could not parse"):
        load_case(write(tmp_path, "c.json", "{"))


def test_missing_answer(tmp_path):
    with pytest.raises(CaseError, match="answer"):
        load_case(write(tmp_path, "c.json", json.dumps({"sources": []})))


def test_missing_file(tmp_path):
    with pytest.raises(CaseError):
        load_case(tmp_path / "nope.json")


def test_case_hash_is_stable(tmp_path):
    path = write(tmp_path, "c.json", json.dumps({"answer": "a"}))
    assert load_case(path).sha256() == load_case(path).sha256()
