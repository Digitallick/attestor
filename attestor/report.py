from __future__ import annotations

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from attestor.models import Report, Severity, Verdict

VERDICT_STYLE = {Verdict.PASS: "bold green", Verdict.WARN: "bold yellow", Verdict.BLOCK: "bold red"}
SEVERITY_STYLE = {Severity.BLOCK: "red", Severity.WARN: "yellow", Severity.INFO: "dim"}


def render(report: Report, console: Console) -> None:
    header = Text.assemble(
        (f" {report.verdict.value} ", f"reverse {VERDICT_STYLE[report.verdict]}"),
        "  ",
        (report.case_id, "bold"),
        (f"   pack {report.pack} · {len(report.checks_run)} checks · "
         f"{len(report.findings)} findings", "dim"),
    )
    console.print(header)
    if not report.findings:
        console.print("  Nothing to flag.", style="green")
        return

    table = Table(box=box.SIMPLE_HEAD, pad_edge=False, show_edge=False, expand=False)
    table.add_column("Level", no_wrap=True)
    table.add_column("Check", no_wrap=True, style="cyan")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Finding", ratio=3)
    table.add_column("Rule", style="dim", ratio=2)
    for f in report.findings:
        detail = f.message
        if passage := f.evidence.get("closest_passage"):
            detail += f'\n[dim]source: "{passage}"[/dim]'
        elif masked := f.evidence.get("masked"):
            detail += f" [dim]({masked})[/dim]"
        table.add_row(
            Text(f.severity.value.upper(), style=SEVERITY_STYLE[f.severity]),
            f.check_id,
            str(f.claim_index or "-"),
            detail,
            "\n".join(f.regulatory_refs),
        )
    console.print(table)
