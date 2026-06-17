"""Tool shadowing and cross-server contamination detection."""

from __future__ import annotations

import re
from collections import defaultdict

from ..mcp_client import ServerSnapshot
from ..models import Finding
from ..taxonomy import AttackClass, Severity
from .classifier import _matches, _normalize

_MANIP_VERBS = [
    r"instead of",
    r"override",
    r"redirect",
    r"when (the )?user",
    r"before calling",
    r"also call",
    r"reroute",
    r"bypass",
    r"ignore",
]


def check_shadowing(snapshots: list[ServerSnapshot]) -> list[Finding]:
    findings: list[Finding] = []

    # Cross-server duplicate tool names — a malicious server can shadow a trusted one.
    by_name: dict[str, list[str]] = defaultdict(list)
    for s in snapshots:
        for t in s.tools:
            by_name[t.name].append(s.server_name)
    for name, servers in by_name.items():
        uniq = sorted(set(servers))
        if len(uniq) > 1:
            findings.append(
                Finding.from_attack(
                    AttackClass.TOOL_SHADOWING,
                    target=f"tool:{name}",
                    detail=(
                        f"The tool name '{name}' is exposed by multiple connected servers "
                        f"({', '.join(uniq)}). A malicious server can shadow the trusted one and "
                        "intercept calls routed to that name."
                    ),
                    evidence=f"servers: {', '.join(uniq)}",
                    confidence=0.8,
                )
            )

    # Cross-tool reference with manipulative phrasing.
    all_names = {t.name for s in snapshots for t in s.tools}
    for s in snapshots:
        for t in s.tools:
            desc = _normalize(t.description or "")
            if not desc:
                continue
            referenced = sorted(n for n in all_names if n != t.name and _matches(desc, [_normalize(n)]))
            if referenced and any(re.search(v, desc) for v in _MANIP_VERBS):
                findings.append(
                    Finding.from_attack(
                        AttackClass.TOOL_SHADOWING,
                        target=t.qualified_name,
                        severity=Severity.MEDIUM,
                        detail=(
                            f"Tool '{t.name}' references other tools ({', '.join(referenced)}) with "
                            "manipulative phrasing, which can hijack calls intended for them."
                        ),
                        evidence=desc[:160],
                        confidence=0.55,
                    )
                )

    return findings
