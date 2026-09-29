from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.table import Table

from attestor.audit import append_record, verify_chain
from attestor.checks import all_checks
from attestor.engine import check_case
from attestor.errors import AttestorError
from attestor.judge import make_judge
from attestor.loader import load_case
from attestor.models import Verdict
from attestor.policy import DEFAULT_PACK, list_packs, load_policy, pack_text, policy_from_dict
from attestor.report import render

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Compliance checks and audit evidence for LLM outputs.",
)
console = Console()
err_console = Console(stderr=True)

POLICY_FILE = Path("attestor.yaml")
_VERDICT_RANK = {Verdict.PASS: 0, Verdict.WARN: 1, Verdict.BLOCK: 2}


def _fail(message: str) -> NoReturn:
    err_console.print(f"[red]error:[/red] {message}", highlight=False, soft_wrap=True)
    raise typer.Exit(3)


@app.command()
def check(
    cases: Annotated[list[Path], typer.Argument(help="Case files (JSON or YAML).")],
    policy: Annotated[
        Path | None,
        typer.Option("--policy", "-p", help="Policy file. Defaults to ./attestor.yaml, "
                     "then the finance pack."),
    ] = None,
    judge: Annotated[
        str | None, typer.Option(help="Send uncertain claims to an LLM judge: 'claude'.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON instead of a table.")] = False,
    no_audit: Annotated[bool, typer.Option("--no-audit", help="Skip the audit log.")] = False,
    strict: Annotated[bool, typer.Option(help="Exit 2 when the worst verdict is WARN.")] = False,
) -> None:
    """Check one or more cases and print a report."""
    try:
        policy_path = policy or (POLICY_FILE if POLICY_FILE.exists() else None)
        pol = load_policy(policy_path)
        judge_impl = make_judge(judge or pol.judge.provider, pol.judge.model)
        reports = [check_case(load_case(p), pol, judge=judge_impl) for p in cases]
        if pol.audit.enabled and not no_audit:
            for report in reports:
                append_record(pol.audit.path, report)
    except AttestorError as exc:
        _fail(str(exc))

    if as_json:
        payload = [r.model_dump(mode="json") for r in reports]
        typer.echo(json.dumps(payload[0] if len(payload) == 1 else payload, indent=2))
    else:
        for report in reports:
            render(report, console)
            console.print()

    worst = max((r.verdict for r in reports), key=_VERDICT_RANK.__getitem__)
    if worst is Verdict.BLOCK:
        raise typer.Exit(1)
    if worst is Verdict.WARN and strict:
        raise typer.Exit(2)


@app.command("verify-log")
def verify_log(
    path: Annotated[Path, typer.Argument(help="Audit log to verify.")] = Path(
        ".attestor/audit.jsonl"
    ),
) -> None:
    """Check that no audit record was edited, removed or reordered."""
    try:
        status = verify_chain(path)
    except AttestorError as exc:
        _fail(str(exc))
    if status.ok:
        console.print(f"[green]ok[/green] {status.records} records, chain intact")
        return
    console.print(f"[red]broken[/red] at record {status.broken_at}: {status.reason}")
    raise typer.Exit(1)


@app.command("list-checks")
def list_checks(
    pack: Annotated[str, typer.Option(help="Pack whose settings to show.")] = DEFAULT_PACK,
) -> None:
    """Show the available checks and how a pack configures them."""
    try:
        pol = policy_from_dict({"pack": pack})
    except AttestorError as exc:
        _fail(str(exc))
    table = Table(title=f"{pack} pack")
    table.add_column("Check", no_wrap=True, min_width=max(map(len, all_checks())))
    table.add_column("What it looks for")
    table.add_column("Level")
    table.add_column("Rules")
    for check_id, check_cls in all_checks().items():
        cfg = pol.config_for(check_id)
        level = (cfg.severity or check_cls.default_severity).value if cfg.enabled else "off"
        table.add_row(check_id, check_cls.title, level, "\n".join(cfg.regulatory_refs))
    console.print(table)


@app.command("list-packs")
def list_packs_cmd() -> None:
    """Show the bundled policy packs."""
    for name, description in list_packs().items():
        console.print(f"[bold]{name}[/bold]  {description}")


@app.command()
def init(
    pack: Annotated[str, typer.Option(help="Pack to start from.")] = DEFAULT_PACK,
    path: Annotated[Path, typer.Option(help="Where to write the policy.")] = POLICY_FILE,
    force: Annotated[bool, typer.Option(help="Overwrite an existing file.")] = False,
) -> None:
    """Write a policy file based on one of the packs."""
    if path.exists() and not force:
        _fail(f"{path} already exists (use --force to overwrite)")
    try:
        text = pack_text(pack)
    except AttestorError as exc:
        _fail(str(exc))
    path.write_text(text, encoding="utf-8")
    console.print(f"wrote {path} from the {pack} pack")

