"""Top-level scan orchestration: connect to a target, analyze it, return a Report."""

from __future__ import annotations

from .mcp_client import ServerSnapshot, connect_http, connect_stdio
from .models import Report, TargetInfo
from .static import run_detectors


def analyze(
    snapshots: list[ServerSnapshot],
    *,
    target: TargetInfo | None = None,
    classifier=None,
) -> Report:
    """Run the static engine over already-captured snapshots (no I/O — easy to unit test)."""
    findings = run_detectors(snapshots, classifier=classifier)
    tools = [t for s in snapshots for t in s.tools]
    if target is None:
        name = snapshots[0].server_name if snapshots else None
        target = TargetInfo(transport="config", server_name=name)
    return Report(target=target, tools=tools, findings=findings)


async def scan_stdio(command: str, *, classifier=None, **connect_kwargs) -> Report:
    snap = await connect_stdio(command, **connect_kwargs)
    target = TargetInfo(transport="stdio", command=command, server_name=snap.server_name)
    return analyze([snap], target=target, classifier=classifier)


async def scan_http(url: str, *, classifier=None, **connect_kwargs) -> Report:
    snap = await connect_http(url, **connect_kwargs)
    target = TargetInfo(transport="http", url=url, server_name=snap.server_name)
    return analyze([snap], target=target, classifier=classifier)
