"""Generate the example HTML dashboards in examples/.

Real-server dashboards scan the published tool specs in fixtures/real-world/catalog.json (tool *metadata*
only, no server is executed). The walkthrough dashboards are re-rendered from their saved scan JSON in
examples/. Run from the repo root:

    uv run python scripts/generate_examples.py
"""

from __future__ import annotations

import json
from pathlib import Path

from agentinel.mcp_client import ServerSnapshot
from agentinel.models import Report, TargetInfo, ToolInfo
from agentinel.report.html import _MARK, _font_css, to_html
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

# Walkthroughs: re-render the saved scans of the bundled fixture servers, keeping their original timestamps.
for name in ("poisoned", "fleet", "clean"):
    saved = Report.model_validate_json((OUT / f"{name}-scan.json").read_text())
    (OUT / f"{name}-scan.html").write_text(to_html(saved))
    print("wrote", f"{name}-scan.html")

# The GitHub Pages landing page, in the same brand as the reports.
page = (ROOT / "scripts" / "index.template.html").read_text().replace("{FONTS}", _font_css()).replace("{MARK}", _MARK)
(OUT / "index.html").write_text(page)
print("wrote index.html")
