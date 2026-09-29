from types import SimpleNamespace

import pytest

from attestor.errors import JudgeError
from attestor.judge import (
    DEFAULT_JUDGE_MODEL,
    AnthropicJudge,
    JudgeVerdict,
    _Assessment,
    make_judge,
)
from attestor.models import Source


class FakeClient:
    def __init__(self, response=None, error=None):
        self.kwargs = None
        self._response, self._error = response, error
        self.beta = SimpleNamespace(messages=SimpleNamespace(parse=self._parse))

    def _parse(self, **kwargs):
        self.kwargs = kwargs
        if self._error:
            raise self._error
        return self._response


def reply(parsed, stop_reason="end_turn"):
    return SimpleNamespace(parsed_output=parsed, stop_reason=stop_reason)


SOURCES = [Source(id="S1", text="Revenue was $10 million.")]


def test_parses_structured_verdict():
    client = FakeClient(reply(_Assessment(supported=True, rationale="r", quote="q")))
    verdict = AnthropicJudge(client=client).assess("Revenue hit $10 million.", SOURCES)
    assert verdict == JudgeVerdict(True, "r", "q")
    assert client.kwargs["model"] == DEFAULT_JUDGE_MODEL
    assert 'id="S1"' in client.kwargs["messages"][0]["content"]
    assert "temperature" not in client.kwargs


def test_refusal_is_an_error():
    client = FakeClient(reply(None, stop_reason="refusal"))
    with pytest.raises(JudgeError, match="declined"):
        AnthropicJudge(client=client).assess("x", SOURCES)


def test_transport_errors_become_judge_errors():
    client = FakeClient(error=RuntimeError("timeout"))
    with pytest.raises(JudgeError, match="timeout"):
        AnthropicJudge(client=client).assess("x", SOURCES)


def test_missing_verdict_is_an_error():
    with pytest.raises(JudgeError):
        AnthropicJudge(client=FakeClient(reply(None))).assess("x", SOURCES)


def test_make_judge():
    assert make_judge("none") is None
    assert make_judge(None) is None
    with pytest.raises(JudgeError, match="unknown judge"):
        make_judge("gpt")
