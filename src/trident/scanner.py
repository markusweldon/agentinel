"""Top-level scan orchestration: connect to a target, analyze it, return a Report."""

from __future__ import annotations

from .config import parse_config
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


async def scan_config(path: str, *, classifier=None, timeout: float = 30.0, quiet: bool = True) -> Report:
    """Scan every MCP server declared in a config file and analyze them together as a fleet."""
    specs = parse_config(path)
    snapshots: list[ServerSnapshot] = []
    notes: list[str] = []
    for spec in specs:
        try:
            if spec.transport == "stdio":
                snap = await connect_stdio(spec.command, env=spec.env, timeout=timeout, quiet=quiet)
            else:
                snap = await connect_http(spec.url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - one bad server should not abort the fleet scan
            notes.append(f"could not connect to '{spec.name}': {exc}")
            continue
        snap.server_name = spec.name
        snap.env = spec.env
        for tool in snap.tools:
            tool.server = spec.name  # use the config-declared name consistently
        snapshots.append(snap)
    report = analyze(snapshots, target=TargetInfo(transport="config", command=str(path)), classifier=classifier)
    report.notes = notes
    return report
