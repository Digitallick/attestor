"""Regenerate docs/demo.svg from the bad memo example."""

from pathlib import Path

from rich.console import Console

from attestor import check_case, load_case
from attestor.report import render

ROOT = Path(__file__).resolve().parent.parent

console = Console(record=True, width=118)
console.print("[bold]$[/bold] attestor check examples/cases/bad_memo.json\n")
render(check_case(load_case(ROOT / "examples/cases/bad_memo.json")), console)
console.save_svg(str(ROOT / "docs/demo.svg"), title="attestor")
