"""Generate example HTML dashboards from the published tool specs in the real-world catalog.

These scan tool *metadata* only — no server is executed. Source data lives in
fixtures/real-world/catalog.json. Run from the repo root:

    uv run python scripts/generate_examples.py
"""

from __future__ import annotations

import json
from pathlib import Path

from agentinel.mcp_client import ServerSnapshot
from agentinel.models import TargetInfo, ToolInfo
from agentinel.report.html import to_html
from agentinel.scanner import analyze

ROOT = Path(__file__).resolve().parent.parent
CATALOG = json.loads((ROOT / "fixtures" / "real-world" / "catalog.json").read_text())
OUT = ROOT / "examples"
STAMP = "from published tool specs"


def _snap(name: str) -> ServerSnapshot:
    tools = [ToolInfo(server=name, name=t["name"], description=t["description"]) for t in CATALOG[name]]
    return ServerSnapshot(server_name=name, tools=tools)


def _write(filename: str, report) -> None:
    report.generated_at = STAMP
    (OUT / filename).write_text(to_html(report))
    print("wrote", filename)


# Per-server dashboards for notable real servers.
for name in ("github", "notion", "kubernetes"):
    report = analyze([_snap(name)], target=TargetInfo(transport="config", server_name=name))
    _write(f"{name}-scan.html", report)

# A real-world fleet: individually-safe servers that combine into a cross-server trifecta.
fleet = ["fetch", "filesystem", "slack"]
report = analyze(
    [_snap(n) for n in fleet],
    target=TargetInfo(transport="config", server_name="real-world fleet (fetch + filesystem + Slack)"),
)
_write("realworld-fleet-scan.html", report)
