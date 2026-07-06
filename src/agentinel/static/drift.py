"""Rug-pull / drift detection.

A server can silently change a tool's description, parameters, or behavior *after* you approved
it — a "rug pull." This records a baseline fingerprint of every tool's definition and, on later
scans, flags any tool whose definition changed since the baseline.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..models import Finding, ToolInfo
from ..taxonomy import AttackClass, Severity


def _fingerprint(tool: ToolInfo) -> str:
    # Include annotations: a server can flip readOnlyHint/destructiveHint/openWorldHint (which drive
    # the A/C classification) with no description or schema change — that is a rug pull we must catch.
    blob = "|".join(
        [
            tool.description or "",
            json.dumps(tool.input_schema or {}, sort_keys=True, default=str),
            json.dumps(tool.annotations or {}, sort_keys=True, default=str),
        ]
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def apply_drift(tools: list[ToolInfo], baseline_path: str | Path) -> tuple[list[Finding], bool]:
    """Compare tools to the baseline, return (findings, baseline_was_just_established).

    On first run the baseline is created and no findings are returned. On later runs, any tool whose
    fingerprint changed produces a RUG_PULL finding, and the baseline is refreshed to the current state.
    """
    path = Path(baseline_path)
    old: dict | None = None
    if path.exists():
        try:
            old = json.loads(path.read_text()).get("servers")
        except (json.JSONDecodeError, OSError):
            old = None

    current: dict[str, dict] = {}
    for t in tools:
        current.setdefault(t.server, {})[t.name] = {
            "hash": _fingerprint(t),
            "description": t.description or "",
        }

    findings: list[Finding] = []
    if old is not None:
        for t in tools:
            prev = (old.get(t.server) or {}).get(t.name)
            if prev and prev.get("hash") != current[t.server][t.name]["hash"]:
                findings.append(
                    Finding.from_attack(
                        AttackClass.RUG_PULL,
                        target=t.qualified_name,
                        severity=Severity.HIGH,
                        detail=(
                            "This tool's definition changed since the recorded baseline. A server can "
                            "silently mutate a tool after you approved it (a rug pull) — re-review it "
                            "before continuing to trust it."
                        ),
                        evidence=f"was: {prev.get('description', '')[:80]!r} -> now: {(t.description or '')[:80]!r}",
                        confidence=0.9,
                    )
                )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "servers": current}, indent=2))
    return findings, old is None
