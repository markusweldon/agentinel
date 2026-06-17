"""trident command-line interface."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import typer
from rich.console import Console

from . import __version__
from .prober import probe_http, probe_stdio
from .report.html import to_html
from .report.sarif import to_sarif
from .report.terminal import render_report
from .scanner import scan_http, scan_stdio
from .taxonomy import Severity

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Red-team and statically audit MCP servers against the OWASP Agentic Top 10.",
)
err = Console(stderr=True)


def _write_outputs(report, json_out: Path | None, sarif_out: Path | None, html_out: Path | None) -> None:
    if json_out:
        json_out.write_text(report.model_dump_json(indent=2))
        err.print(f"[dim]wrote JSON report -> {json_out}[/dim]")
    if sarif_out:
        sarif_out.write_text(json.dumps(to_sarif(report), indent=2))
        err.print(f"[dim]wrote SARIF report -> {sarif_out}[/dim]")
    if html_out:
        html_out.write_text(to_html(report))
        err.print(f"[dim]wrote HTML report -> {html_out}[/dim]")


@app.command()
def scan(
    stdio: str = typer.Option(None, "--stdio", help="Launch an MCP server with this command and scan it."),
    http: str = typer.Option(None, "--http", help="Connect to a streamable-HTTP MCP server URL and scan it."),
    json_out: Path = typer.Option(None, "--json", help="Write the full report as JSON to this path."),
    sarif_out: Path = typer.Option(None, "--sarif", help="Write findings as SARIF (GitHub code scanning)."),
    html_out: Path = typer.Option(None, "--html", help="Write an HTML scorecard to this path."),
    fail_on: Severity = typer.Option(
        Severity.HIGH,
        "--fail-on",
        case_sensitive=False,
        help="Exit non-zero if any finding is at or above this severity.",
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Connection timeout in seconds."),
    inherit_env: bool = typer.Option(
        False, "--inherit-env", help="Forward the current environment to the stdio server."
    ),
    quiet: bool = typer.Option(True, "--quiet/--no-quiet", help="Suppress the scanned server's stderr."),
) -> None:
    """Statically scan a single MCP server (static analysis only; no tools are invoked)."""
    if bool(stdio) == bool(http):
        err.print("[red]Provide exactly one of --stdio '<command>' or --http <url>.[/red]")
        raise typer.Exit(2)

    try:
        if stdio:
            report = asyncio.run(scan_stdio(stdio, timeout=timeout, inherit_env=inherit_env, quiet=quiet))
        else:
            report = asyncio.run(scan_http(http, timeout=timeout))
    except Exception as exc:  # noqa: BLE001 - surface any connection/enumeration failure cleanly
        err.print(f"[red]Failed to scan target:[/red] {exc}")
        raise typer.Exit(2) from exc

    render_report(report, fail_on=fail_on)
    _write_outputs(report, json_out, sarif_out, html_out)
    raise typer.Exit(0 if report.gate(fail_on) else 1)


@app.command()
def probe(
    stdio: str = typer.Option(None, "--stdio", help="Launch an MCP server with this command and probe it."),
    http: str = typer.Option(None, "--http", help="Connect to a streamable-HTTP MCP server URL and probe it."),
    rounds: int = typer.Option(3, "--rounds", help="Adaptive attack rounds per objective."),
    agent_model: str = typer.Option("claude-sonnet-4-6", "--agent-model", help="Model acting as the agent under test."),
    attacker_model: str = typer.Option(
        "claude-opus-4-8", "--attacker-model", help="Model crafting adaptive injections."
    ),
    no_static: bool = typer.Option(False, "--no-static", help="Skip the static scan; run the probe only."),
    json_out: Path = typer.Option(None, "--json", help="Write the full report as JSON to this path."),
    sarif_out: Path = typer.Option(None, "--sarif", help="Write findings as SARIF (GitHub code scanning)."),
    html_out: Path = typer.Option(None, "--html", help="Write an HTML scorecard to this path."),
    fail_on: Severity = typer.Option(
        Severity.HIGH, "--fail-on", case_sensitive=False, help="Exit non-zero at or above this severity."
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Connection timeout in seconds."),
    quiet: bool = typer.Option(True, "--quiet/--no-quiet", help="Suppress the probed server's stderr."),
) -> None:
    """Adaptively red-team a live MCP server. Requires ANTHROPIC_API_KEY.

    WARNING: only probe servers you own or are explicitly authorized to test. See ETHICS.md.
    """
    if bool(stdio) == bool(http):
        err.print("[red]Provide exactly one of --stdio '<command>' or --http <url>.[/red]")
        raise typer.Exit(2)
    if not os.environ.get("ANTHROPIC_API_KEY"):
        err.print("[red]ANTHROPIC_API_KEY is not set — the probe needs it to drive the models.[/red]")
        raise typer.Exit(2)

    try:
        if stdio:
            report = asyncio.run(
                probe_stdio(
                    stdio,
                    rounds=rounds,
                    agent_model=agent_model,
                    attacker_model=attacker_model,
                    timeout=timeout,
                    quiet=quiet,
                    include_static=not no_static,
                )
            )
        else:
            report = asyncio.run(
                probe_http(
                    http,
                    rounds=rounds,
                    agent_model=agent_model,
                    attacker_model=attacker_model,
                    timeout=timeout,
                    include_static=not no_static,
                )
            )
    except Exception as exc:  # noqa: BLE001
        err.print(f"[red]Probe failed:[/red] {exc}")
        raise typer.Exit(2) from exc

    render_report(report, fail_on=fail_on)
    _write_outputs(report, json_out, sarif_out, html_out)
    raise typer.Exit(0 if report.gate(fail_on) else 1)


@app.command()
def version() -> None:
    """Print the trident version."""
    typer.echo(__version__)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
