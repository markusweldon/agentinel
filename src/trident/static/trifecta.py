"""Lethal Trifecta / Rule-of-Two detection — trident's signature static check.

Flags two conditions:
  1. A single tool that itself holds all three dangerous axes (CRITICAL).
  2. A server whose *combined* toolset spans all three axes (HIGH) — the agent connected to it
     can be steered to chain those tools into exfiltration, even if no single tool is dangerous.

When only two of three axes are present we emit an INFO note: the server is one capability away
from completing the trifecta.

References: Simon Willison's "Lethal Trifecta" and Meta's "Agents Rule of Two".
"""

from __future__ import annotations

from functools import reduce

from ..mcp_client import ServerSnapshot
from ..models import CapabilityAxes, Finding, ToolInfo
from ..taxonomy import AttackClass, Severity


def _contributors(tools: list[ToolInfo], axis: str) -> list[str]:
    return [t.qualified_name for t in tools if t.axes and getattr(t.axes, axis)]


def check_trifecta(snapshot: ServerSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    tools = [t for t in snapshot.tools if t.axes is not None]
    if not tools:
        return findings

    # 1. Single tool that is itself the whole trifecta.
    for t in tools:
        ax = t.axes
        if ax and ax.is_trifecta:
            findings.append(
                Finding.from_attack(
                    AttackClass.LETHAL_TRIFECTA,
                    target=t.qualified_name,
                    severity=Severity.CRITICAL,
                    title="Single tool holds the entire lethal trifecta",
                    detail=(
                        f"Tool '{t.name}' alone provides untrusted-input (A), sensitive-access (B), "
                        f"and external-comms (C). A single injected instruction routed to this tool "
                        f"can read sensitive data and exfiltrate it in one step."
                    ),
                    evidence="; ".join(f"{k}: {v}" for k, v in (ax.rationale or {}).items()),
                    confidence=0.7,
                )
            )

    # 2. Server-aggregate trifecta across the toolset.
    union: CapabilityAxes = reduce(lambda acc, t: acc.merged_with(t.axes), tools, CapabilityAxes())
    server_target = f"server:{snapshot.server_name}"

    if union.is_trifecta:
        a = _contributors(tools, "untrusted_input")
        b = _contributors(tools, "sensitive_access")
        c = _contributors(tools, "external_comms")
        findings.append(
            Finding.from_attack(
                AttackClass.LETHAL_TRIFECTA,
                target=server_target,
                severity=Severity.HIGH,
                detail=(
                    "This server's combined toolset spans all three lethal-trifecta axes, so an agent "
                    "using it can be steered to chain them into data exfiltration or unauthorized "
                    f"action. Contributors — A (untrusted-input): {', '.join(a) or 'none'}; "
                    f"B (sensitive-access): {', '.join(b) or 'none'}; "
                    f"C (external-comms): {', '.join(c) or 'none'}."
                ),
                evidence="axes present: A+B+C",
                confidence=0.75,
            )
        )
    elif union.count == 2:
        findings.append(
            Finding.from_attack(
                AttackClass.LETHAL_TRIFECTA,
                target=server_target,
                severity=Severity.INFO,
                title="Two of three lethal-trifecta axes present",
                detail=(
                    f"This server's toolset already holds two trifecta axes ({', '.join(union.labels)}). "
                    "Adding a tool with the third axis — or connecting it alongside another server that "
                    "provides it — would complete the lethal trifecta."
                ),
                evidence="axes present: " + ", ".join(union.labels),
                confidence=0.6,
            )
        )

    return findings
