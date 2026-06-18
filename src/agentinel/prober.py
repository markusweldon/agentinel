"""Top-level probe orchestration: connect, classify, adaptively red-team, assemble a Report."""

from __future__ import annotations

from .dynamic import AnthropicChat, run_adaptive_probe
from .dynamic.llm import Chat
from .mcp_client import connect_http, connect_stdio
from .models import Finding, ProbeReport, Report, TargetInfo
from .static import classify_snapshot, run_detectors

DEFAULT_AGENT_MODEL = "claude-sonnet-4-6"
DEFAULT_ATTACKER_MODEL = "claude-opus-4-8"


def _probe_findings(probe: ProbeReport) -> list[Finding]:
    findings: list[Finding] = []
    for a in probe.attempts:
        if a.succeeded:
            findings.append(
                Finding.from_attack(
                    a.attack_class,
                    target="agent-under-test",
                    detail=f"Adaptive probe breached the agent in {a.rounds} round(s). Objective: {a.objective}",
                    evidence=(a.payload or "")[:200],
                    confidence=0.9,
                )
            )
    return findings


def _assemble(snap, target: TargetInfo, probe: ProbeReport, include_static: bool) -> Report:
    findings = run_detectors([snap]) if include_static else []
    findings += _probe_findings(probe)
    return Report(target=target, tools=snap.tools, findings=findings, probe=probe)


async def probe_stdio(
    command: str,
    *,
    rounds: int = 3,
    agent_model: str = DEFAULT_AGENT_MODEL,
    attacker_model: str = DEFAULT_ATTACKER_MODEL,
    timeout: float = 30.0,
    quiet: bool = True,
    include_static: bool = True,
    agent_chat: Chat | None = None,
    attacker_chat: Chat | None = None,
) -> Report:
    snap = await connect_stdio(command, quiet=quiet, timeout=timeout)
    classify_snapshot(snap)
    probe = run_adaptive_probe(
        agent_chat=agent_chat or AnthropicChat(agent_model),
        attacker_chat=attacker_chat or AnthropicChat(attacker_model),
        tools=snap.tools,
        rounds=rounds,
    )
    target = TargetInfo(transport="stdio", command=command, server_name=snap.server_name)
    return _assemble(snap, target, probe, include_static)


async def probe_http(
    url: str,
    *,
    rounds: int = 3,
    agent_model: str = DEFAULT_AGENT_MODEL,
    attacker_model: str = DEFAULT_ATTACKER_MODEL,
    timeout: float = 30.0,
    include_static: bool = True,
    agent_chat: Chat | None = None,
    attacker_chat: Chat | None = None,
) -> Report:
    snap = await connect_http(url, timeout=timeout)
    classify_snapshot(snap)
    probe = run_adaptive_probe(
        agent_chat=agent_chat or AnthropicChat(agent_model),
        attacker_chat=attacker_chat or AnthropicChat(attacker_model),
        tools=snap.tools,
        rounds=rounds,
    )
    target = TargetInfo(transport="http", url=url, server_name=snap.server_name)
    return _assemble(snap, target, probe, include_static)
