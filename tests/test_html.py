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


def test_html_embeds_brand_fonts_and_shows_a_verdict():
    target = TargetInfo(transport="stdio", command="x", server_name="s")
    risky = Report(
        target=target,
        tools=[ToolInfo(server="s", name="x", axes=CapabilityAxes(untrusted_input=True))],
        findings=[Finding.from_attack(AttackClass.TOOL_POISONING, target="s:x", detail="d")],
    )
    clean = Report(target=target, tools=[ToolInfo(server="s", name="x", axes=CapabilityAxes())], findings=[])

    risky_html, clean_html = to_html(risky), to_html(clean)
    assert "@font-face" in risky_html and "data:font/woff2;base64," in risky_html  # self-contained, no network fetch
    assert "FAIL" in risky_html
    assert "PASS" in clean_html and "No findings" in clean_html
