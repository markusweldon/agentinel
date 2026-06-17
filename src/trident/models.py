"""Pydantic models shared across the static and dynamic engines."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .taxonomy import ASICategory, AttackClass, Severity, attack_info


class CapabilityAxes(BaseModel):
    """The three Rule-of-Two axes for a tool or an aggregated toolset.

    A = ingests untrusted / external content, B = touches sensitive data or systems,
    C = can change state or communicate externally. Holding all three is the Lethal Trifecta.
    """

    untrusted_input: bool = False  # A
    sensitive_access: bool = False  # B
    external_comms: bool = False  # C
    rationale: dict[str, str] = Field(default_factory=dict)

    @property
    def count(self) -> int:
        return int(self.untrusted_input) + int(self.sensitive_access) + int(self.external_comms)

    @property
    def is_trifecta(self) -> bool:
        return self.untrusted_input and self.sensitive_access and self.external_comms

    @property
    def labels(self) -> list[str]:
        out: list[str] = []
        if self.untrusted_input:
            out.append("A:untrusted-input")
        if self.sensitive_access:
            out.append("B:sensitive-access")
        if self.external_comms:
            out.append("C:external-comms")
        return out

    def merged_with(self, other: CapabilityAxes) -> CapabilityAxes:
        """OR-combine two axis sets (used to aggregate across an agent's full toolset)."""
        rationale = {**self.rationale, **other.rationale}
        return CapabilityAxes(
            untrusted_input=self.untrusted_input or other.untrusted_input,
            sensitive_access=self.sensitive_access or other.sensitive_access,
            external_comms=self.external_comms or other.external_comms,
            rationale=rationale,
        )


class ToolInfo(BaseModel):
    """A normalized view of one MCP tool, enriched with capability classification."""

    server: str
    name: str
    description: str | None = None
    input_schema: dict = Field(default_factory=dict)
    annotations: dict | None = None
    axes: CapabilityAxes | None = None

    @property
    def qualified_name(self) -> str:
        return f"{self.server}:{self.name}"


class Finding(BaseModel):
    """A single security finding, mapped to an OWASP ASI category."""

    attack_class: AttackClass
    asi: ASICategory
    severity: Severity
    title: str
    detail: str
    target: str
    evidence: str | None = None
    remediation: str
    confidence: float = 0.8
    references: list[str] = Field(default_factory=list)

    @classmethod
    def from_attack(
        cls,
        attack_class: AttackClass,
        *,
        target: str,
        detail: str,
        evidence: str | None = None,
        severity: Severity | None = None,
        confidence: float = 0.8,
        title: str | None = None,
        remediation: str | None = None,
        extra_references: list[str] | None = None,
    ) -> Finding:
        """Build a finding, inheriting ASI, severity, title, and references from the taxonomy."""
        info = attack_info(attack_class)
        references = list(info.references) + list(extra_references or [])
        return cls(
            attack_class=attack_class,
            asi=info.asi,
            severity=severity or info.default_severity,
            title=title or info.title,
            detail=detail,
            target=target,
            evidence=evidence,
            remediation=remediation or info.remediation,
            confidence=confidence,
            references=references,
        )


class TargetInfo(BaseModel):
    """What was scanned."""

    transport: Literal["stdio", "http", "config"]
    command: str | None = None
    url: str | None = None
    server_name: str | None = None

    @property
    def label(self) -> str:
        return self.server_name or self.url or self.command or self.transport


class ProbeAttempt(BaseModel):
    """One adaptive red-team attempt against a live target."""

    asi: ASICategory
    attack_class: AttackClass
    objective: str
    payload: str
    succeeded: bool
    rounds: int = 1
    judge_rationale: str | None = None
    transcript: list[dict] = Field(default_factory=list)


class ProbeReport(BaseModel):
    """Aggregated results of a dynamic probe run."""

    attempts: list[ProbeAttempt] = Field(default_factory=list)
    canary: str | None = None

    @property
    def succeeded(self) -> list[ProbeAttempt]:
        return [a for a in self.attempts if a.succeeded]

    @property
    def scorecard(self) -> dict[ASICategory, dict[str, int]]:
        """Per-ASI {attempted, breached} counts."""
        card: dict[ASICategory, dict[str, int]] = {}
        for a in self.attempts:
            row = card.setdefault(a.asi, {"attempted": 0, "breached": 0})
            row["attempted"] += 1
            if a.succeeded:
                row["breached"] += 1
        return card


class Report(BaseModel):
    """The full result of a scan and/or probe run."""

    target: TargetInfo
    tools: list[ToolInfo] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    probe: ProbeReport | None = None
    generated_at: str | None = None

    @property
    def severity_counts(self) -> dict[Severity, int]:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @property
    def asi_counts(self) -> dict[ASICategory, int]:
        counts: dict[ASICategory, int] = {}
        for f in self.findings:
            counts[f.asi] = counts.get(f.asi, 0) + 1
        return counts

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def gate(self, threshold: Severity) -> bool:
        """Return True if the scan passes (no finding at or above ``threshold``)."""
        return all(f.severity.rank < threshold.rank for f in self.findings)

    def sorted_findings(self) -> list[Finding]:
        """Findings sorted by severity (highest first), then ASI id."""
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.asi.value, f.target))
