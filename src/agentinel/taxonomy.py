"""The taxonomy spine: OWASP Agentic Top 10 (2026), severities, and attack classes.

Every finding agentinel emits references an :class:`AttackClass`, which carries a default
:class:`ASICategory` mapping, severity, remediation, and canonical references. Keeping this
metadata in one place means detectors stay terse and the taxonomy stays consistent.

Sources:
- OWASP Top 10 for Agentic Applications (2026):
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    """Finding severity, ordered by :attr:`rank`."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class ASICategory(StrEnum):
    """OWASP Top 10 for Agentic Applications (2026): ASI01–ASI10."""

    ASI01 = "ASI01"
    ASI02 = "ASI02"
    ASI03 = "ASI03"
    ASI04 = "ASI04"
    ASI05 = "ASI05"
    ASI06 = "ASI06"
    ASI07 = "ASI07"
    ASI08 = "ASI08"
    ASI09 = "ASI09"
    ASI10 = "ASI10"

    @property
    def title(self) -> str:  # type: ignore[override]  # intentionally shadows str.title; never called as a method here
        return _ASI_TITLES[self]

    @property
    def description(self) -> str:
        return _ASI_DESCRIPTIONS[self]

    @property
    def label(self) -> str:
        return f"{self.value}: {self.title}"


_ASI_TITLES: dict[ASICategory, str] = {
    ASICategory.ASI01: "Agent Goal Hijack",
    ASICategory.ASI02: "Tool Misuse and Exploitation",
    ASICategory.ASI03: "Identity and Privilege Abuse",
    ASICategory.ASI04: "Agentic Supply Chain Vulnerabilities",
    ASICategory.ASI05: "Unexpected Code Execution",
    ASICategory.ASI06: "Memory and Context Poisoning",
    ASICategory.ASI07: "Insecure Inter-Agent Communication",
    ASICategory.ASI08: "Cascading Failures",
    ASICategory.ASI09: "Human-Agent Trust Exploitation",
    ASICategory.ASI10: "Rogue Agents",
}

_ASI_DESCRIPTIONS: dict[ASICategory, str] = {
    ASICategory.ASI01: "Attackers alter the agent's objectives or plan via prompt injection or poisoned content.",
    ASICategory.ASI02: "The agent abuses legitimate tools in unsafe ways within its granted privileges.",
    ASICategory.ASI03: "The agent inherits or escalates over-scoped or delegated credentials (the attribution gap).",
    ASICategory.ASI04: "Compromised tools, plugins, MCP servers, models, or external components.",
    ASICategory.ASI05: "The agent generates or runs code or commands unsafely.",
    ASICategory.ASI06: "Attackers poison agent memory, context, or retrieval stores.",
    ASICategory.ASI07: "Spoofing or tampering in agent-to-agent protocols, discovery, and semantic validation.",
    ASICategory.ASI08: "A single fault propagates across agents or workflows.",
    ASICategory.ASI09: "Anthropomorphism or authority bias is weaponized against human oversight.",
    ASICategory.ASI10: "Behavioral drift, collusion, or self-replication beyond the initial compromise.",
}


class AttackClass(StrEnum):
    """Concrete attack techniques agentinel detects (static) or attempts (dynamic)."""

    TOOL_POISONING = "tool_poisoning"
    RUG_PULL = "rug_pull"
    TOOL_SHADOWING = "tool_shadowing"
    INDIRECT_INJECTION = "indirect_injection"
    LETHAL_TRIFECTA = "lethal_trifecta"
    UNSAFE_CODE_EXECUTION = "unsafe_code_execution"
    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    SECRETS_EXPOSURE = "secrets_exposure"
    TOKEN_PASSTHROUGH = "token_passthrough"
    UNPINNED_SERVER = "unpinned_server"
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"


@dataclass(frozen=True)
class AttackInfo:
    title: str
    asi: ASICategory
    default_severity: Severity
    description: str
    remediation: str
    references: tuple[str, ...] = ()


# Canonical references reused across attack classes.
_REF_TOOL_POISONING = "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"
_REF_TOXIC_FLOW = "https://invariantlabs.ai/blog/mcp-github-vulnerability"
_REF_ETDI = "https://arxiv.org/pdf/2506.01333"
_REF_TRIFECTA = "https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/"
_REF_RULE_OF_TWO = "https://ai.meta.com/blog/practical-ai-agent-security/"
_REF_ATTACKER_SECOND = "https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/"
_REF_OWASP_ASI = "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"


ATTACK_METADATA: dict[AttackClass, AttackInfo] = {
    AttackClass.TOOL_POISONING: AttackInfo(
        title="Tool poisoning (hidden instructions in tool metadata)",
        asi=ASICategory.ASI01,
        default_severity=Severity.HIGH,
        description=(
            "A tool's description, parameter docs, or schema contains instructions aimed at the "
            "model rather than the human — invisible to the user but read by the agent, hijacking "
            "its behavior."
        ),
        remediation=(
            "Treat tool metadata as untrusted. Strip or sandbox tool descriptions, pin servers to "
            "reviewed versions, and require human approval before installing third-party tools."
        ),
        references=(_REF_TOOL_POISONING, _REF_OWASP_ASI),
    ),
    AttackClass.RUG_PULL: AttackInfo(
        title="Rug pull risk (tool may mutate after approval)",
        asi=ASICategory.ASI04,
        default_severity=Severity.MEDIUM,
        description=(
            "The server can silently change a tool's description, parameters, or behavior after the "
            "user approved it, turning a trusted tool malicious."
        ),
        remediation=(
            "Pin the server to an immutable version or digest, verify tool definitions against a "
            "reviewed snapshot, and re-prompt for approval when a tool definition changes."
        ),
        references=(_REF_ETDI, _REF_TOOL_POISONING),
    ),
    AttackClass.TOOL_SHADOWING: AttackInfo(
        title="Tool shadowing / cross-server name collision",
        asi=ASICategory.ASI04,
        default_severity=Severity.HIGH,
        description=(
            "Two servers expose tools with the same name, or one server's tool description references "
            "another server's tools — letting a malicious server intercept or redirect calls meant for "
            "a trusted one."
        ),
        remediation=(
            "Namespace tools per server, disallow duplicate tool names across connected servers, and "
            "isolate untrusted servers from trusted ones."
        ),
        references=(_REF_TOOL_POISONING, _REF_TOXIC_FLOW),
    ),
    AttackClass.INDIRECT_INJECTION: AttackInfo(
        title="Indirect prompt injection via tool output",
        asi=ASICategory.ASI01,
        default_severity=Severity.HIGH,
        description=("Untrusted content returned by a tool or resource carries instructions the agent then follows."),
        remediation=(
            "Quarantine tool output as data, never instructions; constrain what the agent may do with "
            "retrieved content; and apply the Rule of Two to limit blast radius."
        ),
        references=(_REF_ATTACKER_SECOND, _REF_OWASP_ASI),
    ),
    AttackClass.LETHAL_TRIFECTA: AttackInfo(
        title="Lethal Trifecta / Rule-of-Two violation",
        asi=ASICategory.ASI02,
        default_severity=Severity.HIGH,
        description=(
            "An agent (or its combined toolset) holds all three dangerous capabilities at once: access "
            "to untrusted content (A), access to sensitive data or systems (B), and the ability to "
            "change state or communicate externally (C). Any prompt injection can then exfiltrate or "
            "act. Meta's Rule of Two says hold at most two without a human in the loop."
        ),
        remediation=(
            "Break the trifecta: remove one axis, split capabilities across isolated agents, or require "
            "human approval for the state-changing / external-comms step."
        ),
        references=(_REF_TRIFECTA, _REF_RULE_OF_TWO),
    ),
    AttackClass.UNSAFE_CODE_EXECUTION: AttackInfo(
        title="Unsafe code or command execution surface",
        asi=ASICategory.ASI05,
        default_severity=Severity.HIGH,
        description=(
            "A tool exposes shell, eval, or arbitrary-code execution to the agent, letting an injected "
            "instruction run commands on the host."
        ),
        remediation=(
            "Sandbox execution, drop privileges, allow-list commands, and require human approval for "
            "any code-execution tool."
        ),
        references=(_REF_OWASP_ASI,),
    ),
    AttackClass.EXCESSIVE_PERMISSIONS: AttackInfo(
        title="Excessive or wildcard permissions",
        asi=ASICategory.ASI03,
        default_severity=Severity.MEDIUM,
        description=(
            "A tool requests over-broad scope — wildcard filesystem or network access, unrestricted "
            "paths, or admin-level capability beyond what its purpose needs."
        ),
        remediation=(
            "Apply least privilege: scope filesystem roots, restrict outbound hosts, and narrow tool "
            "parameters to the minimum required."
        ),
        references=(_REF_OWASP_ASI,),
    ),
    AttackClass.SECRETS_EXPOSURE: AttackInfo(
        title="Secret exposed in server configuration",
        asi=ASICategory.ASI03,
        default_severity=Severity.HIGH,
        description=(
            "An API key, token, or credential is hardcoded into the server's launch command, "
            "environment, or arguments where it can leak."
        ),
        remediation=(
            "Load secrets from a secret manager or runtime environment, never commit them to config, "
            "and rotate any exposed credential."
        ),
        references=(_REF_OWASP_ASI,),
    ),
    AttackClass.TOKEN_PASSTHROUGH: AttackInfo(
        title="Token passthrough / confused deputy",
        asi=ASICategory.ASI03,
        default_severity=Severity.HIGH,
        description=(
            "The server reuses or forwards an access token to act with the user's authority across a "
            "trust boundary, a classic confused-deputy condition."
        ),
        remediation=(
            "Use audience-bound, task-scoped tokens; validate the token's intended audience; and never "
            "forward an inbound token to a downstream service."
        ),
        references=(_REF_OWASP_ASI,),
    ),
    AttackClass.UNPINNED_SERVER: AttackInfo(
        title="Server pinned to a mutable version",
        asi=ASICategory.ASI04,
        default_severity=Severity.LOW,
        description=(
            "The server is launched from a mutable reference (e.g. 'latest', an unpinned npm/PyPI "
            "package, or a moving git ref), so its code and tool definitions can change under you."
        ),
        remediation=("Pin to an exact version or content digest and review upgrades before adopting them."),
        references=(_REF_ETDI,),
    ),
    AttackClass.PROMPT_INJECTION: AttackInfo(
        title="Prompt injection succeeded (dynamic probe)",
        asi=ASICategory.ASI01,
        default_severity=Severity.HIGH,
        description=(
            "An adaptive injection payload steered the agent off its task or into following attacker "
            "instructions during live probing."
        ),
        remediation=(
            "Harden the system prompt, isolate untrusted content, and add input/output guardrails; note "
            "that static defenses often fail adaptive attacks (the attacker moves second)."
        ),
        references=(_REF_ATTACKER_SECOND,),
    ),
    AttackClass.DATA_EXFILTRATION: AttackInfo(
        title="Data exfiltration succeeded (dynamic probe)",
        asi=ASICategory.ASI02,
        default_severity=Severity.CRITICAL,
        description=(
            "During live probing the agent was induced to leak a planted canary secret or send "
            "sensitive data to an attacker-controlled destination."
        ),
        remediation=(
            "Remove one leg of the lethal trifecta, gate external-comms tools behind human approval, and "
            "add egress controls / canary monitoring."
        ),
        references=(_REF_TRIFECTA, _REF_RULE_OF_TWO),
    ),
}


def attack_info(attack_class: AttackClass) -> AttackInfo:
    """Return the metadata record for an attack class."""
    return ATTACK_METADATA[attack_class]
