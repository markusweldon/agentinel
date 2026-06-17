"""SARIF output is well-formed and consumable by GitHub code scanning."""

from __future__ import annotations

from trident.models import Finding, Report, TargetInfo
from trident.report.sarif import to_sarif
from trident.taxonomy import AttackClass

_VALID_LEVELS = {"error", "warning", "note", "none"}


def test_sarif_document_structure():
    findings = [
        Finding.from_attack(AttackClass.LETHAL_TRIFECTA, target="server:x", detail="trifecta"),
        Finding.from_attack(AttackClass.TOOL_POISONING, target="x:tool", detail="poisoned"),
    ]
    report = Report(target=TargetInfo(transport="stdio", command="x"), findings=findings)
    doc = to_sarif(report)

    assert doc["version"] == "2.1.0"
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "trident"
    assert {r["id"] for r in driver["rules"]} == {"lethal_trifecta", "tool_poisoning"}

    results = doc["runs"][0]["results"]
    assert len(results) == 2
    for r in results:
        assert r["level"] in _VALID_LEVELS
        assert r["ruleId"] in {"lethal_trifecta", "tool_poisoning"}
        assert r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]


def test_sarif_security_severity_present():
    report = Report(
        target=TargetInfo(transport="stdio", command="x"),
        findings=[Finding.from_attack(AttackClass.LETHAL_TRIFECTA, target="server:x", detail="d")],
    )
    rule = to_sarif(report)["runs"][0]["tool"]["driver"]["rules"][0]
    assert "security-severity" in rule["properties"]
