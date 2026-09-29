from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


def canonical_json(data: Any) -> bytes:
    """Stable JSON encoding used for every hash attestor records."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class Severity(str, Enum):
    INFO = "info"
    WARN = "warn"
    BLOCK = "block"


SEVERITY_RANK = {Severity.INFO: 0, Severity.WARN: 1, Severity.BLOCK: 2}


class Verdict(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"


class Source(BaseModel):
    id: str = Field(min_length=1)
    title: str | None = None
    text: str


class Case(BaseModel):
    id: str = Field(min_length=1)
    answer: str
    sources: list[Source] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _unique_source_ids(self) -> Case:
        seen: set[str] = set()
        for source in self.sources:
            if source.id in seen:
                raise ValueError(f"duplicate source id '{source.id}'")
            seen.add(source.id)
        return self

    def source(self, source_id: str) -> Source | None:
        return next((s for s in self.sources if s.id == source_id), None)

    def sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.model_dump(mode="json"))).hexdigest()


class Claim(BaseModel):
    index: int
    text: str
    citations: list[str] = Field(default_factory=list)
    is_factual: bool = False


class Finding(BaseModel):
    check_id: str
    severity: Severity
    message: str
    claim_index: int | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    regulatory_refs: list[str] = Field(default_factory=list)


class Report(BaseModel):
    case_id: str
    verdict: Verdict
    findings: list[Finding]
    checks_run: list[str]
    pack: str
    case_sha256: str
    policy_sha256: str
    judge_calls: list[dict[str, Any]] = Field(default_factory=list)
    attestor_version: str
    timestamp: str
