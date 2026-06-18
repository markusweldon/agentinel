"""Rich terminal rendering of a scan/probe Report."""

from __future__ import annotations

from rich.box import SIMPLE_HEAVY
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import Report
from ..taxonomy import Severity

_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _sev_text(sev: Severity) -> Text:
    return Text(sev.value.upper(), style=_SEV_STYLE[sev])


def _mark(on: bool) -> Text:
    return Text("●", style="red") if on else Text("·", style="dim")


def _capability_table(report: Report) -> Table | None:
    classified = [t for t in report.tools if t.axes is not None]
    if not classified:
        return None
    table = Table(title="Capability matrix (Rule of Two)", box=SIMPLE_HEAVY, title_justify="left")
    table.add_column("Tool", overflow="fold")
    table.add_column("A\nuntrusted", justify="center")
    table.add_column("B\nsensitive", justify="center")
    table.add_column("C\nexternal", justify="center")
    for t in sorted(classified, key=lambda x: (not x.axes.is_trifecta, x.name)):
        ax = t.axes
        table.add_row(
            t.qualified_name,
            _mark(ax.untrusted_input),
            _mark(ax.sensitive_access),
            _mark(ax.external_comms),
            style="bold red" if ax.is_trifecta else None,
        )
    return table


def _findings_table(report: Report) -> Table:
    table = Table(box=SIMPLE_HEAVY, show_lines=False)
    table.add_column("Severity")
    table.add_column("OWASP")
    table.add_column("Class", overflow="fold")
    table.add_column("Target", overflow="fold")
    table.add_column("Title", overflow="fold")
    for f in report.sorted_findings():
        table.add_row(_sev_text(f.severity), f.asi.value, f.attack_class.value, f.target, f.title)
    return table


def _render_probe(report: Report, console: Console) -> None:
    probe = report.probe
    if probe is None:
        return
    console.print()
    console.print(
        Panel(Text("Adaptive probe — attacker moves second", style="bold"), border_style="magenta", expand=False)
    )
    if probe.canary:
        console.print(Text(f"planted canary: {probe.canary}", style="dim"))
    table = Table(box=SIMPLE_HEAVY)
    table.add_column("OWASP")
    table.add_column("Objective", overflow="fold")
    table.add_column("Result")
    table.add_column("Rounds", justify="right")
    for a in probe.attempts:
        result = Text("BREACHED", style="bold red") if a.succeeded else Text("withstood", style="green")
        table.add_row(a.asi.value, a.objective, result, str(a.rounds))
    console.print(table)


def render_report(
    report: Report,
    *,
    console: Console | None = None,
    fail_on: Severity | None = None,
    show_details: bool = True,
) -> None:
    console = console or Console()

    tgt = report.target
    header = Text()
    header.append("Agentinel", style="bold")
    header.append(" — MCP security scan\n")
    header.append(f"target:  {tgt.label}\n", style="dim")
    header.append(f"server:  {tgt.server_name or '?'}   tools: {len(report.tools)}", style="dim")
    console.print(Panel(header, expand=False, border_style="cyan"))

    for note in report.notes:
        console.print(Text(f"  ⚠ {note}", style="yellow"))

    cap = _capability_table(report)
    if cap is not None:
        console.print(cap)

    _render_probe(report, console)

    if not report.findings:
        console.print("\n[bold green]No findings.[/bold green] ✅\n")
        return

    console.print()
    console.print(_findings_table(report))

    if show_details:
        console.print()
        for f in report.sorted_findings():
            line = Text.assemble("● ", _sev_text(f.severity), f"  {f.title}  ", (f"[{f.target}]", "dim"))
            console.print(line)
            console.print(Text(f"   {f.detail}", style="white"))
            if f.evidence:
                console.print(Text(f"   evidence: {f.evidence}", style="dim"))
            console.print(Text(f"   fix: {f.remediation}", style="green"))
            console.print(Text(f"   {f.asi.label}  ·  confidence {f.confidence:.2f}", style="dim"))
            console.print()

    counts = report.severity_counts
    parts = [
        f"[{_SEV_STYLE[s]}]{counts[s]} {s.value}[/]"
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
        if counts[s]
    ]
    console.print(f"{len(report.findings)} findings  (" + ", ".join(parts) + ")")
    if fail_on is not None:
        verdict = "[bold green]PASS[/]" if report.gate(fail_on) else "[bold red]FAIL[/]"
        console.print(f"result: {verdict}  (--fail-on {fail_on.value})")
