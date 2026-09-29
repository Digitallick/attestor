from __future__ import annotations

import hashlib
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from attestor.checks import all_checks
from attestor.errors import PolicyError
from attestor.judge import DEFAULT_JUDGE_MODEL
from attestor.models import Severity, canonical_json

DEFAULT_PACK = "finance"
_PACKS = files("attestor") / "packs"


class CheckConfig(BaseModel):
    """Common settings plus any check-specific options (thresholds, phrase lists)."""

    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    severity: Severity | None = None
    regulatory_refs: list[str] = Field(default_factory=list)

    @property
    def options(self) -> dict[str, Any]:
        return dict(self.model_extra or {})


class JudgeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["none", "anthropic", "claude"] = "none"
    model: str = DEFAULT_JUDGE_MODEL


class AuditConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    path: str = ".attestor/audit.jsonl"


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    pack: str = DEFAULT_PACK
    description: str = ""
    checks: dict[str, CheckConfig] = Field(default_factory=dict)
    judge: JudgeConfig = Field(default_factory=JudgeConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)

    @field_validator("checks")
    @classmethod
    def _known_checks(cls, value: dict[str, CheckConfig]) -> dict[str, CheckConfig]:
        known = all_checks()
        unknown = sorted(set(value) - set(known))
        if unknown:
            raise ValueError(
                f"unknown check(s): {', '.join(unknown)}; valid checks: {', '.join(known)}"
            )
        return value

    def config_for(self, check_id: str) -> CheckConfig:
        return self.checks.get(check_id, CheckConfig())

    def sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.model_dump(mode="json"))).hexdigest()


def list_packs() -> dict[str, str]:
    packs = {}
    for entry in sorted(_PACKS.iterdir(), key=lambda e: e.name):
        if entry.name.endswith(".yaml"):
            data = yaml.safe_load(entry.read_text(encoding="utf-8")) or {}
            packs[entry.name.removesuffix(".yaml")] = data.get("description", "")
    return packs


def pack_text(name: str) -> str:
    entry = _PACKS / f"{name}.yaml"
    if not entry.is_file():
        raise PolicyError(f"unknown pack '{name}'; available: {', '.join(list_packs())}")
    return entry.read_text(encoding="utf-8")


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def policy_from_dict(data: dict[str, Any]) -> Policy:
    """Build a policy from user settings layered over the pack they name."""
    if not isinstance(data, dict):
        raise PolicyError("policy must be a mapping")
    base = yaml.safe_load(pack_text(data.get("pack", DEFAULT_PACK))) or {}
    try:
        return Policy.model_validate(_merge(base, data))
    except ValidationError as exc:
        err = exc.errors()[0]
        loc = ".".join(str(part) for part in err["loc"])
        raise PolicyError(f"invalid policy at {loc}: {err['msg']}") from exc


def load_policy(path: str | Path | None = None) -> Policy:
    if path is None:
        return policy_from_dict({})
    p = Path(path)
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"{p}: {exc}") from exc
    return policy_from_dict(data)
