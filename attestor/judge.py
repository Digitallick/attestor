"""Optional LLM judge for claims the lexical scorer can't decide on its own."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel

from attestor.errors import JudgeError
from attestor.models import Source

DEFAULT_JUDGE_MODEL = "claude-opus-5-5"

SYSTEM_PROMPT = """You check whether a claim is supported by the source excerpts you are given.

A claim is supported only if the excerpts state it or directly imply it. Rewording is fine. \
New facts, different figures, or stronger language than the source uses are not supported.

Use only the excerpts, not outside knowledge. Quote the passage you relied on, or leave the \
quote empty when nothing supports the claim. Keep the rationale to one or two sentences."""


@dataclass(frozen=True)
class JudgeVerdict:
    supported: bool
    rationale: str
    quote: str = ""


class Judge(Protocol):
    name: str

    def assess(self, claim: str, sources: Sequence[Source]) -> JudgeVerdict: ...


class _Assessment(BaseModel):
    supported: bool
    rationale: str
    quote: str


class AnthropicJudge:
    def __init__(self, model: str = DEFAULT_JUDGE_MODEL, client=None):
        if client is None:
            try:
                import anthropic
            except ImportError as exc:
                raise JudgeError(
                    "the judge needs the anthropic package: pip install 'attestor[judge]'"
                ) from exc
            client = anthropic.Anthropic()
        self._client = client
        self.model = model
        self.name = f"anthropic:{model}"

    def assess(self, claim: str, sources: Sequence[Source]) -> JudgeVerdict:
        excerpts = "\n\n".join(f'<source id="{s.id}">\n{s.text}\n</source>' for s in sources)
        try:
            response = self._client.beta.messages.parse(
                model=self.model,
                max_tokens=4000,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": f"{excerpts}\n\n<claim>{claim}</claim>"}],
                output_format=_Assessment,
                output_config={"effort": "low"},
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except Exception as exc:  # any failure here must surface as a finding, never a pass
            raise JudgeError(f"judge request failed: {exc}") from exc

        if response.stop_reason == "refusal":
            raise JudgeError("judge declined to assess this claim")
        result = response.parsed_output
        if result is None:
            raise JudgeError("judge returned no usable verdict")
        return JudgeVerdict(result.supported, result.rationale, result.quote)


def make_judge(provider: str | None, model: str = DEFAULT_JUDGE_MODEL) -> Judge | None:
    if provider in (None, "", "none"):
        return None
    if provider in ("anthropic", "claude"):
        return AnthropicJudge(model)
    raise JudgeError(f"unknown judge '{provider}' (supported: claude)")
