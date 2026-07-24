"""Reproduce the aggregate numbers in RESEARCH.md.

Runs agentinel's static engine over every server in fixtures/real-world/catalog.json (tool metadata
only — no server is executed) and prints a per-server verdict plus the aggregate distribution.

    uv run python scripts/analyze_catalog.py
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from agentinel.mcp_client import ServerSnapshot
from agentinel.models import ToolInfo
from agentinel.scanner import analyze

_CATALOG = Path(__file__).resolve().parent.parent / "fixtures" / "real-world" / "catalog.json"
_ORDER = ("LETHAL TRIFECTA", "code execution", "near-trifecta", "clean")


def _verdict(findings) -> str:
    high_tri = any(
        f.attack_class.value == "lethal_trifecta" and f.severity.value in ("high", "critical") for f in findings
    )
    if high_tri:
        return "LETHAL TRIFECTA"
    if any(f.attack_class.value == "unsafe_code_execution" for f in findings):
        return "code execution"
    if any(f.attack_class.value == "lethal_trifecta" for f in findings):
        return "near-trifecta"
    return "clean"


def main() -> None:
    catalog = json.loads(_CATALOG.read_text())
    servers = [k for k in catalog if not k.startswith("_")]
    cats: Counter[str] = Counter()
    classes: Counter[str] = Counter()
    rows: list[tuple[str, str]] = []
    n_tools = 0

    for name in servers:
        tools = [ToolInfo(server=name, name=t["name"], description=t["description"]) for t in catalog[name]]
        n_tools += len(tools)
        findings = analyze([ServerSnapshot(server_name=name, tools=tools)]).findings
        for cls in {f.attack_class.value for f in findings}:
            classes[cls] += 1
        rows.append((name, _verdict(findings)))
        cats[_verdict(findings)] += 1

    n = len(servers)
    print(f"# {n} servers, {n_tools} tools\n")
    for name, verdict in sorted(rows, key=lambda r: _ORDER.index(r[1])):
        print(f"  {name:14} {verdict}")
    print("\n## verdict distribution")
    for v in _ORDER:
        print(f"  {v:16} {cats[v]:2}  ({round(100 * cats[v] / n)}%)")
    print("\n## finding-class prevalence (share of servers)")
    for cls, count in classes.most_common():
        print(f"  {cls:22} {count:2}  ({round(100 * count / n)}%)")


if __name__ == "__main__":
    main()
