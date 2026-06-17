"""Render a Report as a single self-contained HTML scorecard."""

from __future__ import annotations

from jinja2 import Template

from ..models import Report
from ..taxonomy import Severity

_SEV_COLOR = {
    Severity.CRITICAL: "#ff4d4f",
    Severity.HIGH: "#ff7a45",
    Severity.MEDIUM: "#faad14",
    Severity.LOW: "#36cfc9",
    Severity.INFO: "#8c8c8c",
}

_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>trident — {{ server_name }}</title>
<style>
  :root { color-scheme: dark; }
  body { background:#0d1117; color:#c9d1d9; font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; margin:0; padding:32px; }
  .wrap { max-width:900px; margin:0 auto; }
  h1 { font-size:22px; margin:0 0 4px; } h1 small { color:#8b949e; font-weight:400; }
  .meta { color:#8b949e; margin-bottom:20px; }
  .chips span { display:inline-block; padding:3px 10px; border-radius:12px; margin:0 6px 6px 0; font-size:13px; color:#0d1117; font-weight:600; }
  table { width:100%; border-collapse:collapse; margin:14px 0; }
  th,td { text-align:left; padding:7px 10px; border-bottom:1px solid #21262d; }
  th { color:#8b949e; font-weight:600; font-size:13px; }
  .dot { font-weight:700; } .on { color:#ff7a45; } .off { color:#30363d; }
  tr.trifecta td { background:#2d1417; }
  .card { background:#161b22; border:1px solid #30363d; border-left-width:4px; border-radius:6px; padding:12px 14px; margin:10px 0; }
  .badge { font-size:12px; font-weight:700; padding:2px 8px; border-radius:4px; color:#0d1117; }
  .card h3 { margin:0 0 6px; font-size:15px; } .card .tgt { color:#8b949e; font-weight:400; font-size:13px; }
  .card p { margin:6px 0; } .ev { color:#8b949e; font-family:ui-monospace,monospace; font-size:13px; word-break:break-word; }
  .fix { color:#3fb950; } .asi { color:#8b949e; font-size:13px; }
  h2 { font-size:16px; margin:24px 0 6px; border-bottom:1px solid #21262d; padding-bottom:4px; }
  .ok { color:#3fb950; }
</style></head><body><div class="wrap">
  <h1>trident <small>MCP security scorecard</small></h1>
  <div class="meta">server <b>{{ server_name }}</b> &middot; {{ tool_count }} tools &middot; target <code>{{ target_label }}</code></div>
  <div class="chips">
    {% for c in chips %}<span style="background:{{ c.color }}">{{ c.count }} {{ c.label }}</span>{% endfor %}
    {% if not chips %}<span class="ok">No findings</span>{% endif %}
  </div>

  {% if tools %}
  <h2>Capability matrix (Rule of Two)</h2>
  <table><thead><tr><th>Tool</th><th>A · untrusted</th><th>B · sensitive</th><th>C · external</th></tr></thead><tbody>
    {% for t in tools %}<tr class="{{ 'trifecta' if t.trifecta }}">
      <td>{{ t.name }}</td>
      <td class="dot {{ 'on' if t.a else 'off' }}">{{ '●' if t.a else '·' }}</td>
      <td class="dot {{ 'on' if t.b else 'off' }}">{{ '●' if t.b else '·' }}</td>
      <td class="dot {{ 'on' if t.c else 'off' }}">{{ '●' if t.c else '·' }}</td>
    </tr>{% endfor %}
  </tbody></table>
  {% endif %}

  {% if attempts %}
  <h2>Adaptive probe — attacker moves second</h2>
  <table><thead><tr><th>OWASP</th><th>Objective</th><th>Result</th><th>Rounds</th></tr></thead><tbody>
    {% for a in attempts %}<tr><td>{{ a.asi }}</td><td>{{ a.objective }}</td>
      <td style="color:{{ '#ff4d4f' if a.breached else '#3fb950' }};font-weight:700">{{ 'BREACHED' if a.breached else 'withstood' }}</td>
      <td>{{ a.rounds }}</td></tr>{% endfor %}
  </tbody></table>
  {% endif %}

  {% if findings %}<h2>Findings</h2>{% endif %}
  {% for f in findings %}
  <div class="card" style="border-left-color:{{ f.color }}">
    <h3><span class="badge" style="background:{{ f.color }}">{{ f.sev }}</span> {{ f.title }} <span class="tgt">— {{ f.target }}</span></h3>
    <p>{{ f.detail }}</p>
    {% if f.evidence %}<p class="ev">evidence: {{ f.evidence }}</p>{% endif %}
    <p class="fix">fix: {{ f.remediation }}</p>
    <p class="asi">{{ f.asi }} &middot; confidence {{ f.confidence }}</p>
  </div>
  {% endfor %}
</div></body></html>"""


def to_html(report: Report) -> str:
    chips = [
        {"label": s.value, "count": report.severity_counts[s], "color": _SEV_COLOR[s]}
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
        if report.severity_counts[s]
    ]
    tools = [
        {
            "name": t.qualified_name,
            "a": t.axes.untrusted_input,
            "b": t.axes.sensitive_access,
            "c": t.axes.external_comms,
            "trifecta": t.axes.is_trifecta,
        }
        for t in report.tools
        if t.axes
    ]
    attempts = []
    if report.probe:
        attempts = [
            {"asi": a.asi.value, "objective": a.objective, "breached": a.succeeded, "rounds": a.rounds}
            for a in report.probe.attempts
        ]
    findings = [
        {
            "sev": f.severity.value.upper(),
            "color": _SEV_COLOR[f.severity],
            "title": f.title,
            "target": f.target,
            "detail": f.detail,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "asi": f.asi.label,
            "confidence": f"{f.confidence:.2f}",
        }
        for f in report.sorted_findings()
    ]
    return Template(_TEMPLATE, autoescape=True).render(
        server_name=report.target.server_name or "?",
        target_label=report.target.label,
        tool_count=len(report.tools),
        chips=chips,
        tools=tools,
        attempts=attempts,
        findings=findings,
    )
