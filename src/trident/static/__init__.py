"""Static analysis engine: classify tools, then run every detector over the snapshots."""

from __future__ import annotations

from ..mcp_client import ServerSnapshot
from ..models import Finding
from .capabilities import check_capabilities
from .classifier import classify_snapshot, classify_tool
from .fleet import check_fleet_trifecta
from .shadowing import check_shadowing
from .tool_poisoning import check_tool_poisoning
from .trifecta import check_trifecta

__all__ = [
    "run_detectors",
    "classify_snapshot",
    "classify_tool",
    "check_capabilities",
    "check_fleet_trifecta",
    "check_shadowing",
    "check_tool_poisoning",
    "check_trifecta",
]


def run_detectors(snapshots: list[ServerSnapshot], *, classifier=None) -> list[Finding]:
    """Classify and run all static detectors. Returns the combined findings."""
    findings: list[Finding] = []
    for snap in snapshots:
        classify_snapshot(snap, classifier or classify_tool)
        findings += check_tool_poisoning(snap)
        findings += check_capabilities(snap)
        findings += check_trifecta(snap)
    findings += check_shadowing(snapshots)  # cross-server
    findings += check_fleet_trifecta(snapshots)  # cross-server trifecta
    return findings
