"""Fleet-level (cross-server) Lethal Trifecta detection.

The most dangerous trifecta is often the one no single server creates: server A ingests
untrusted content, server B reaches sensitive data, server C can exfiltrate — and an agent
connected to all three can be chained across them. This fires only when the combination spans
multiple servers and no single server is already a full trifecta (that case is caught per-server).
"""

from __future__ import annotations

from functools import reduce

from ..mcp_client import ServerSnapshot
from ..models import CapabilityAxes, Finding
from ..taxonomy import AttackClass, Severity


def _server_union(snapshot: ServerSnapshot) -> CapabilityAxes:
    axes = [t.axes for t in snapshot.tools if t.axes]
    return reduce(lambda acc, ax: acc.merged_with(ax), axes, CapabilityAxes())


def check_fleet_trifecta(snapshots: list[ServerSnapshot]) -> list[Finding]:
    if len(snapshots) < 2:
        return []
    classified = [t for s in snapshots for t in s.tools if t.axes]
    if not classified:
        return []
    # A single-server trifecta is already reported by the per-server check.
    if any(_server_union(s).is_trifecta for s in snapshots):
        return []
    union = reduce(lambda acc, t: acc.merged_with(t.axes), classified, CapabilityAxes())
    if not union.is_trifecta:
        return []

    def servers_for(axis: str) -> list[str]:
        return sorted({t.server for t in classified if getattr(t.axes, axis)})

    a = servers_for("untrusted_input")
    b = servers_for("sensitive_access")
    c = servers_for("external_comms")
    return [
        Finding.from_attack(
            AttackClass.LETHAL_TRIFECTA,
            target="fleet",
            severity=Severity.HIGH,
            title="Cross-server lethal trifecta across connected servers",
            detail=(
                "No single server is a full trifecta, but the connected fleet combines all three axes. "
                f"A (untrusted-input): {', '.join(a)}; B (sensitive-access): {', '.join(b)}; "
                f"C (external-comms): {', '.join(c)}. An agent connected to all of these can be injected "
                "through one server and steered to read sensitive data and exfiltrate it through another."
            ),
            evidence="cross-server A+B+C",
            confidence=0.7,
        )
    ]
