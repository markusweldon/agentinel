"""Tool-poisoning detection: instructions hidden in tool metadata or server instructions.

Scans every tool description, parameter description, and the server-level instructions for:
  - invisible / bidi / tag Unicode used to smuggle hidden text,
  - prompt-injection phrasing (instruction overrides, concealment from the user, coerced actions),
  - references to credential files an honest tool description would never mention.

Reference: Invariant Labs, "MCP Tool Poisoning Attacks".
"""

from __future__ import annotations

import re

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


def _snippet(text: str, start: int, end: int, pad: int = 24) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    out = text[s:e].replace("\n", " ").strip()
    return (("…" if s > 0 else "") + out + ("…" if e < len(text) else ""))[:160]


def _scan_text(text: str, *, target: str, where: str) -> list[Finding]:
    findings: list[Finding] = []
    if not text:
        return findings

    # Invisible / bidi / tag characters.
    invisible = [m.start() for m in _INVISIBLE_RE.finditer(text)]
    if invisible:
        codepoints = sorted({f"U+{ord(text[i]):04X}" for i in invisible})
        findings.append(
            Finding.from_attack(
                AttackClass.TOOL_POISONING,
                target=target,
                severity=Severity.HIGH,
                detail=(
                    f"The {where} contains {len(invisible)} invisible/bidirectional Unicode "
                    f"character(s) ({', '.join(codepoints)}) — a common vehicle for hiding "
                    "instructions from human reviewers while the model still reads them."
                ),
                evidence=f"hidden codepoints: {', '.join(codepoints)}",
                confidence=0.95,
            )
        )

    lowered = text.lower()
    for pattern, label, confidence in _INJECTION_PATTERNS + _SENSITIVE_FILE_PATTERNS:
        m = re.search(pattern, lowered)
        if m:
            findings.append(
                Finding.from_attack(
                    AttackClass.TOOL_POISONING,
                    target=target,
                    severity=Severity.HIGH if confidence >= 0.7 else Severity.MEDIUM,
                    detail=(
                        f"The {where} contains text resembling a hidden instruction ({label}). "
                        "Tool metadata is read by the agent and must not carry directives."
                    ),
                    evidence=_snippet(text, m.start(), m.end()),
                    confidence=confidence,
                )
            )
    return findings


def check_tool_poisoning(snapshot: ServerSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    for t in snapshot.tools:
        findings += _scan_text(t.description or "", target=t.qualified_name, where="tool description")
        props = (t.input_schema or {}).get("properties", {})
        if isinstance(props, dict):
            for pname, pinfo in props.items():
                if isinstance(pinfo, dict) and pinfo.get("description"):
                    findings += _scan_text(
                        str(pinfo["description"]),
                        target=t.qualified_name,
                        where=f"description of parameter '{pname}'",
                    )
    if snapshot.instructions:
        findings += _scan_text(
            snapshot.instructions,
            target=f"server:{snapshot.server_name}",
            where="server instructions",
        )
    return findings
