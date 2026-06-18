"""Tool-poisoning detection: instructions hidden in tool metadata or server instructions.

Scans every tool description, parameter description, and the server-level instructions for:
  - invisible / bidi / tag Unicode used to smuggle hidden text,
  - prompt-injection phrasing (instruction overrides, concealment from the user, coerced actions),
  - references to credential files an honest tool description would never mention.

All signals found on a single tool are grouped into one finding (rather than one finding per
matched pattern) to keep reports readable.

Reference: Invariant Labs, "MCP Tool Poisoning Attacks".
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..mcp_client import ServerSnapshot
from ..models import Finding
from ..taxonomy import AttackClass, Severity

# Zero-width, bidi-override, word-joiner, BOM, and Unicode tag characters (ASCII smuggling).
_INVISIBLE_RE = re.compile("[​-‏‪-‮⁠-⁤⁪-⁯﻿￹-￻]|[\U000e0000-\U000e007f]")

# (pattern, human label, confidence)
_INJECTION_PATTERNS: list[tuple[str, str, float]] = [
    (
        r"ignore (all |the )?(previous|above|prior|earlier) (instruction|context|message|prompt)",
        "instruction override",
        0.9,
    ),
    (r"disregard (all |the )?(previous|above|prior|earlier)", "instruction override", 0.85),
    (r"do not (tell|inform|notify|mention|reveal|disclose)[^.]{0,30}\buser\b", "concealment from the user", 0.9),
    (r"without (telling|informing|notifying|alerting) the user", "concealment from the user", 0.9),
    (r"before (using|calling|invoking|doing|running) (this|any|anything)", "preconditioned hidden action", 0.7),
    (r"you (must|should|need to) (always|first|secretly|silently)", "coerced behavior", 0.75),
    (r"always (read|send|include|append|forward|call|attach)", "coerced exfiltration/behavior", 0.7),
    (r"<\s*(important|secret|system|admin|instruction)s?\s*>", "hidden directive tags", 0.85),
    (r"\b(system prompt|developer message)\b", "system-prompt reference", 0.5),
    (r"\b(as an ai|you are now|new instructions?)\b", "role override", 0.6),
]

# Credential-file references that almost never appear in an honest tool description.
_SENSITIVE_FILE_PATTERNS: list[tuple[str, str, float]] = [
    (r"\.ssh\b|id_rsa|id_ed25519", "SSH private key path", 0.85),
    (r"/etc/(passwd|shadow)", "system credential file", 0.85),
    (r"\.aws/credentials|aws_secret_access_key", "AWS credentials", 0.85),
    (r"(read|cat|open|load)[^.]{0,20}\.env\b", "environment secrets file", 0.8),
]


@dataclass
class _Signal:
    severity: Severity
    confidence: float
    label: str
    snippet: str
    where: str


def _snippet(text: str, start: int, end: int, pad: int = 24) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    out = text[s:e].replace("\n", " ").strip()
    return (("…" if s > 0 else "") + out + ("…" if e < len(text) else ""))[:160]


def _scan_text(text: str, *, where: str) -> list[_Signal]:
    signals: list[_Signal] = []
    if not text:
        return signals

    invisible = [m.start() for m in _INVISIBLE_RE.finditer(text)]
    if invisible:
        codepoints = sorted({f"U+{ord(text[i]):04X}" for i in invisible})
        signals.append(
            _Signal(
                Severity.HIGH,
                0.95,
                f"invisible/bidi Unicode ({len(invisible)} chars)",
                f"hidden codepoints: {', '.join(codepoints)}",
                where,
            )
        )

    lowered = text.lower()
    for pattern, label, confidence in _INJECTION_PATTERNS + _SENSITIVE_FILE_PATTERNS:
        m = re.search(pattern, lowered)
        if m:
            severity = Severity.HIGH if confidence >= 0.7 else Severity.MEDIUM
            signals.append(_Signal(severity, confidence, label, _snippet(text, m.start(), m.end()), where))
    return signals


def _finding_from_signals(target: str, signals: list[_Signal]) -> Finding:
    labels: list[str] = []
    for s in signals:
        if s.label not in labels:
            labels.append(s.label)
    severity = max(signals, key=lambda s: s.severity.rank).severity
    top = max(signals, key=lambda s: s.confidence)
    n = len(labels)
    return Finding.from_attack(
        AttackClass.TOOL_POISONING,
        target=target,
        severity=severity,
        detail=(
            f"This server's tool metadata carries text resembling hidden instructions "
            f"({n} signal{'s' if n != 1 else ''}: {', '.join(labels)}). Tool metadata is read by the "
            "agent and must not carry directives."
        ),
        evidence=f"{top.where} — {top.snippet}",
        confidence=top.confidence,
    )


def check_tool_poisoning(snapshot: ServerSnapshot) -> list[Finding]:
    findings: list[Finding] = []

    for t in snapshot.tools:
        signals = _scan_text(t.description or "", where="tool description")
        props = (t.input_schema or {}).get("properties", {})
        if isinstance(props, dict):
            for pname, pinfo in props.items():
                if isinstance(pinfo, dict) and pinfo.get("description"):
                    signals += _scan_text(str(pinfo["description"]), where=f"parameter '{pname}'")
        if signals:
            findings.append(_finding_from_signals(t.qualified_name, signals))

    if snapshot.instructions:
        server_signals = _scan_text(snapshot.instructions, where="server instructions")
        if server_signals:
            findings.append(_finding_from_signals(f"server:{snapshot.server_name}", server_signals))

    return findings
