"""Turn a scan into a guard policy: one ``mcp__<server>__<tool>`` -> legs entry per classified tool."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Report, ToolInfo


def tool_legs(tool: ToolInfo) -> str:
    axes = tool.axes
    if axes is None:
        return ""
    return "".join(
        leg for leg, on in (("A", axes.untrusted_input), ("B", axes.sensitive_access), ("C", axes.external_comms)) if on
    )


def policy_from_report(report: Report) -> dict:
    tools = {f"mcp__{t.server}__{t.name}": tool_legs(t) for t in report.tools}
    return {
        "version": 1,
        "generated_from": report.target.label,
        "note": "Legs per MCP tool: A untrusted input, B sensitive data, C external action. Edit freely.",
        "tools": dict(sorted(tools.items())),
    }


def load_report(path: Path) -> Report:
    return Report.model_validate(json.loads(path.read_text()))
