"""Capability and configuration risks: code execution, over-broad scope, secrets, pinning."""

from __future__ import annotations

import re

from ..mcp_client import ServerSnapshot
from ..models import Finding
from ..taxonomy import AttackClass, Severity
from .classifier import _matches, _normalize

_CODE_EXEC_TERMS = [
    "exec",
    "execute",
    "eval",
    "shell",
    "bash",
    "subprocess",
    "run command",
    "run code",
    "system command",
    "terminal",
    "spawn",
    "powershell",
    "arbitrary code",
    "arbitrary command",
]

_BROAD_TERMS = [
    "arbitrary",
    "any path",
    "any file",
    "entire filesystem",
    "all files",
    "wildcard",
    "unrestricted",
    "any host",
    "any url",
    "full access",
    "read any",
    "write any",
    "root access",
    "admin access",
    "sudo",
]

# (regex, label) — matched against the server launch command.
_SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"sk-[A-Za-z0-9]{16,}", "OpenAI-style API key"),
    (r"ghp_[A-Za-z0-9]{20,}", "GitHub token"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "GitHub fine-grained token"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"AIza[0-9A-Za-z_\-]{30,}", "Google API key"),
    (r"(?:api[_-]?key|secret|token|password|passwd)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{12,}", "inline credential"),
    (r"https?://[^/\s:@]+:[^/\s:@]+@", "basic-auth credentials in URL"),
]


def _redact(s: str) -> str:
    s = s.strip().strip("\"'")
    return (s[:4] + "***") if len(s) > 6 else "***"


def check_capabilities(snapshot: ServerSnapshot) -> list[Finding]:
    findings: list[Finding] = []

    for t in snapshot.tools:
        hay = _normalize(f"{t.name} {t.description or ''}")

        exec_hits = _matches(hay, _CODE_EXEC_TERMS)
        if exec_hits:
            findings.append(
                Finding.from_attack(
                    AttackClass.UNSAFE_CODE_EXECUTION,
                    target=t.qualified_name,
                    detail=(
                        f"Tool '{t.name}' exposes code or command execution to the agent, so an "
                        "injected instruction could run commands on the host."
                    ),
                    evidence="matched: " + ", ".join(exec_hits),
                    confidence=0.7,
                )
            )

        broad_hits = _matches(hay, _BROAD_TERMS)
        if broad_hits:
            findings.append(
                Finding.from_attack(
                    AttackClass.EXCESSIVE_PERMISSIONS,
                    target=t.qualified_name,
                    detail=(
                        f"Tool '{t.name}' advertises over-broad access; scope it to the minimum it actually needs."
                    ),
                    evidence="matched: " + ", ".join(broad_hits),
                    confidence=0.6,
                )
            )

    # Launch-command checks (secrets, pinning).
    cmd = snapshot.command or ""
    server_target = f"server:{snapshot.server_name}"
    for pattern, label in _SECRET_PATTERNS:
        m = re.search(pattern, cmd)
        if m:
            findings.append(
                Finding.from_attack(
                    AttackClass.SECRETS_EXPOSURE,
                    target=server_target,
                    detail=f"The server launch command appears to contain a {label}.",
                    evidence=f"{label}: {_redact(m.group(0))}",
                    confidence=0.8,
                )
            )
            break  # one secrets finding per server is enough

    if cmd:
        if re.search(r"@latest\b|:latest\b", cmd):
            findings.append(
                Finding.from_attack(
                    AttackClass.UNPINNED_SERVER,
                    target=server_target,
                    severity=Severity.MEDIUM,
                    detail="The server is launched from a mutable 'latest' reference.",
                    evidence=cmd,
                    confidence=0.8,
                )
            )
        elif re.search(r"\b(npx|uvx|pipx)\b", cmd) and not re.search(r"@\d+\.\d|==\d+\.\d", cmd):
            findings.append(
                Finding.from_attack(
                    AttackClass.UNPINNED_SERVER,
                    target=server_target,
                    detail="The server is launched via npx/uvx/pipx without a pinned version.",
                    evidence=cmd,
                    confidence=0.6,
                )
            )

    return findings
