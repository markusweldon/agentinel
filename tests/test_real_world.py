"""Real-world eval: scan the published tool specs of popular MCP servers (never executed).

These tool definitions were copied from each server's own docs, so they are ground truth agentinel
did not author — the real test of whether the detectors generalize beyond the hand-built fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentinel.mcp_client import ServerSnapshot
from agentinel.models import ToolInfo
from agentinel.scanner import analyze
from agentinel.taxonomy import AttackClass, Severity

_CATALOG = json.loads((Path(__file__).resolve().parent.parent / "fixtures" / "real-world" / "catalog.json").read_text())


def _findings(server: str):
    tools = [ToolInfo(server=server, name=t["name"], description=t["description"]) for t in _CATALOG[server]]
    return analyze([ServerSnapshot(server_name=server, tools=tools)]).findings


def test_full_trifecta_servers_flagged_high():
    # GitHub reads issues/PRs + private repo and writes; Notion reads comments/DB and writes —
    # both span all three axes. (GitHub matches the trifecta Invariant Labs disclosed in the wild.)
    for server in ("github", "notion"):
        fs = _findings(server)
        assert any(f.attack_class is AttackClass.LETHAL_TRIFECTA and f.severity is Severity.HIGH for f in fs), server


def test_benign_servers_have_no_actionable_findings():
    for server in ("fetch", "time", "memory", "postgres", "sentry", "gdrive"):
        actionable = [f for f in _findings(server) if f.severity.rank >= Severity.LOW.rank]
        assert not actionable, f"{server}: {[f.attack_class.value for f in actionable]}"


def test_postgres_readonly_query_not_flagged_as_code_execution():
    # Regression: "execute read-only SQL queries" must not trip the code-execution detector.
    assert not any(f.attack_class is AttackClass.UNSAFE_CODE_EXECUTION for f in _findings("postgres"))


def test_code_execution_servers_flagged():
    # Puppeteer's evaluate runs arbitrary JavaScript; Kubernetes' kubectl_generic runs any command.
    for server in ("puppeteer", "kubernetes"):
        assert any(f.attack_class is AttackClass.UNSAFE_CODE_EXECUTION for f in _findings(server)), server


def test_near_trifecta_servers_are_info_not_high():
    # gitlab is write-focused (no untrusted-content reads), so it must be near-trifecta, NOT a full
    # trifecta — a regression guard for the create_issue-was-mis-flagged-as-untrusted-input fix.
    for server in ("filesystem", "git", "slack", "gitlab", "stripe", "kubernetes"):
        tri = [f for f in _findings(server) if f.attack_class is AttackClass.LETHAL_TRIFECTA]
        assert tri and all(f.severity is Severity.INFO for f in tri), server
