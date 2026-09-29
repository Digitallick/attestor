from __future__ import annotations

import json
from pathlib import Path

import yaml
from pydantic import ValidationError

from attestor.errors import CaseError
from attestor.models import Case


def load_case(path: str | Path) -> Case:
    """Read a case from a JSON or YAML file. The file name is used as the id if none is given."""
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise CaseError(f"{p}: {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise CaseError(f"{p}: not UTF-8 text") from exc

    try:
        data = yaml.safe_load(raw) if p.suffix.lower() in {".yaml", ".yml"} else json.loads(raw)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise CaseError(f"{p}: could not parse ({exc})") from exc

    if not isinstance(data, dict):
        raise CaseError(f"{p}: expected an object at the top level")
    data.setdefault("id", p.stem)

    try:
        return Case.model_validate(data)
    except ValidationError as exc:
        raise CaseError(f"{p}: {_first_error(exc)}") from exc


def _first_error(exc: ValidationError) -> str:
    err = exc.errors()[0]
    loc = ".".join(str(part) for part in err["loc"])
    return f"{loc}: {err['msg']}" if loc else err["msg"]
