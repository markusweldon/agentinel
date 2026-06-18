"""agentinel as an MCP server — assess MCP tool definitions from inside Claude Code / Cursor.

Safe by design: this server never launches a process and never makes a network request. It only
analyzes the tool *metadata you pass in* — the same definitions an assistant already holds for the
servers it is connected to — and returns OWASP Agentic Top 10 findings, including the Lethal
Trifecta analysis.

This deliberately does NOT expose a "scan this command / URL" tool: handing an agent the ability to
launch arbitrary processes or fetch arbitrary URLs is the exact Lethal-Trifecta footgun agentinel
exists to flag. Live scanning that launches or connects to a server lives in the `agentinel` CLI,
where a human supplies the target explicitly.

    claude mcp add agentinel -- uv run agentinel-mcp
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .mcp_client import ServerSnapshot
from .models import Report, TargetInfo, ToolInfo
from .scanner import analyze

mcp = FastMCP("agentinel")


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
def assess_tools(server_name: str, tools: list[dict]) -> dict:
    """Statically assess MCP tool definitions for OWASP Agentic Top 10 risks.

    Pass the tools you want checked, each as an object with at least ``name`` and ``description``
    (optionally ``inputSchema`` and ``annotations``). agentinel analyzes only the metadata you
    provide — it does not launch or connect to anything — and returns findings, including
    Lethal-Trifecta / Rule-of-Two analysis across the toolset.
    """
    snapshot = ServerSnapshot(
        server_name=server_name,
        tools=[
            ToolInfo(
                server=server_name,
                name=str(t.get("name", "")),
                description=t.get("description"),
                input_schema=t.get("inputSchema") or t.get("input_schema") or {},
                annotations=t.get("annotations"),
            )
            for t in tools
        ],
    )
    report = analyze([snapshot], target=TargetInfo(transport="config", server_name=server_name))
    return _summary(report)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
