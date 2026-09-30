from io import StringIO

from helpers import make_case
from rich.console import Console

from attestor import check_case
from attestor.report import render


def test_bracketed_text_in_findings_is_shown_verbatim():
    case = make_case("Margin was 21.5% [S1].", {"S1": "Margin was 17.2% [bold] per filing."})
    out = StringIO()
    render(check_case(case), Console(file=out, width=200))
    assert "[bold]" in out.getvalue()
