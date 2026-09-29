# Contributing

Issues and pull requests are welcome, especially new packs and better detectors.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
ruff check . && pytest
```

A new check is one module in `attestor/checks/` with a class decorated by `@register`, plus tests. A new pack is a YAML file in `attestor/packs/`. Please include the regulatory references you're mapping to and a short note on why they apply.
