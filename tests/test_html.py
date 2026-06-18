"""The HTML scorecard renders and escapes attacker-controlled text."""

from __future__ import annotations

from agentinel.models import CapabilityAxes, Finding, Report, TargetInfo, ToolInfo
from agentinel.report.html import to_html
from agentinel.taxonomy import AttackClass


def test_html_renders_and_escapes_injected_text():
    tool = ToolInfo(
        server="s",
        name="x",
        axes=CapabilityAxes(untrusted_input=True, sensitive_access=True, external_comms=True),
    )
    finding = Finding.from_attack(AttackClass.TOOL_POISONING, target="s:x", detail="<script>alert(1)</script>")
    report = Report(
        target=TargetInfo(transport="stdio", command="x", server_name="s"),
        tools=[tool],
        findings=[finding],
    )
    html = to_html(report)

    assert "<!doctype html>" in html
    assert "Capability matrix" in html
    # autoescape must neutralize injected HTML coming from server-controlled text
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
