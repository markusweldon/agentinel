"""trident as an MCP server — audit other MCP servers from inside Claude Code / Cursor.

Install it as a tool in your assistant, then ask it to scan a server you're about to add:

    claude mcp add trident -- uv run trident-mcp

Only the static `scan` is exposed here (read-only, no tools executed). Adaptive probing stays
in the CLI, where authorization and API-key handling are explicit.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .models import Report
from .scanner import scan_http, scan_stdio

mcp = FastMCP("trident")


def _summary(report: Report) -> dict:
    return {
        "server": report.target.server_name,
        "max_severity": report.max_severity.value if report.max_severity else "none",
        "counts": {s.value: c for s, c in report.severity_counts.items() if c},
        "findings": [
            {
                "severity": f.severity.value,
                "asi": f.asi.label,
                "class": f.attack_class.value,
                "target": f.target,
                "title": f.title,
                "remediation": f.remediation,
            }
            for f in report.sorted_findings()
        ],
    }


@mcp.tool()
async def scan_stdio_server(command: str) -> dict:
    """Statically scan an MCP server launched via the given stdio command.

    Returns a summary of OWASP Agentic Top 10 findings. Does not execute the server's tools.
    """
    return _summary(await scan_stdio(command, quiet=True))


@mcp.tool()
async def scan_http_server(url: str) -> dict:
    """Statically scan a streamable-HTTP MCP server at the given URL."""
    return _summary(await scan_http(url))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
