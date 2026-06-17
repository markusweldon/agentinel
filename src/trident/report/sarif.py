"""Render a Report as SARIF 2.1.0 for GitHub code scanning and other SARIF consumers."""

from __future__ import annotations

from .. import __version__
from ..models import Report
from ..taxonomy import ATTACK_METADATA, AttackClass, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub maps this numeric "security-severity" (CVSS-like) onto its own severity buckets.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}

INFO_URI = "https://github.com/markusweldon/trident"


def _rule(attack_class: AttackClass) -> dict:
    info = ATTACK_METADATA[attack_class]
    return {
        "id": attack_class.value,
        "name": "".join(part.capitalize() for part in attack_class.value.split("_")),
        "shortDescription": {"text": info.title},
        "fullDescription": {"text": info.description},
        "helpUri": info.references[0] if info.references else INFO_URI,
        "help": {"text": info.remediation},
        "defaultConfiguration": {"level": _SARIF_LEVEL[info.default_severity]},
        "properties": {
            "security-severity": _SECURITY_SEVERITY[info.default_severity],
            "tags": ["security", "mcp", info.asi.value],
        },
    }


def to_sarif(report: Report, *, artifact_uri: str = "mcp-server") -> dict:
    """Build a SARIF document. ``artifact_uri`` is the file findings attach to in code scanning."""
    present = sorted({f.attack_class for f in report.findings}, key=lambda a: a.value)
    rules = [_rule(ac) for ac in present]

    results = []
    for f in report.sorted_findings():
        results.append(
            {
                "ruleId": f.attack_class.value,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f"[{f.asi.label}] {f.title} — {f.detail}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_uri},
                        },
                        "logicalLocations": [{"fullyQualifiedName": f.target, "kind": "resource"}],
                    }
                ],
                "partialFingerprints": {"tridentFinding/v1": f"{f.attack_class.value}:{f.target}"},
                "properties": {
                    "asi": f.asi.value,
                    "confidence": f.confidence,
                    "severity": f.severity.value,
                    "evidence": f.evidence or "",
                    "remediation": f.remediation,
                },
            }
        )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "trident",
                        "informationUri": INFO_URI,
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
