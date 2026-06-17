"""Render a Report as a single self-contained HTML security dashboard (no external assets)."""

from __future__ import annotations

from jinja2 import Template

from .. import __version__
from ..models import Report
from ..taxonomy import Severity

_SEV_COLOR = {
    Severity.CRITICAL: "#ff4d4f",
    Severity.HIGH: "#ff7a45",
    Severity.MEDIUM: "#fbbf24",
    Severity.LOW: "#38bdf8",
    Severity.INFO: "#94a3b8",
}

_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>trident — {{ title }}</title>
<style>
  :root{ color-scheme:dark; --bg:#0a0e14; --card:#121821; --card2:#0f141c; --bd:#1f2a37; --tx:#d7e0ea; --mut:#8b97a7; --accent:#22d3ee; --violet:#a78bfa; }
  *{box-sizing:border-box}
  body{margin:0;background:radial-gradient(1200px 600px at 70% -10%, #15202e 0%, var(--bg) 55%);color:var(--tx);
       font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif;-webkit-font-smoothing:antialiased}
  .wrap{max-width:1040px;margin:0 auto;padding:36px 24px 64px}
  header{display:flex;align-items:center;gap:14px;margin-bottom:6px}
  .logo{color:var(--accent);filter:drop-shadow(0 0 10px rgba(34,211,238,.35))}
  h1{font-size:24px;margin:0;letter-spacing:.3px;font-weight:700}
  h1 .v{color:var(--mut);font-weight:500;font-size:13px;margin-left:8px}
  .tag{color:var(--mut);margin:2px 0 22px;font-size:14px}
  .meta{color:var(--mut);font-size:13px;margin-bottom:22px}
  .meta b{color:var(--tx);font-weight:600}
  .meta code{background:var(--card2);border:1px solid var(--bd);border-radius:5px;padding:1px 6px;font-size:12px}
  .note{color:#fbbf24;font-size:13px;margin:4px 0}
  .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin:0 0 18px}
  .kpi{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px 16px}
  .kpi .n{font-size:26px;font-weight:700;line-height:1}
  .kpi .l{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.5px;margin-top:6px}
  .bar{display:flex;height:10px;border-radius:6px;overflow:hidden;margin:6px 0 26px;background:var(--card2);border:1px solid var(--bd)}
  .bar span{display:block;height:100%}
  h2{font-size:13px;text-transform:uppercase;letter-spacing:.8px;color:var(--mut);margin:28px 0 10px;font-weight:600}
  .panel{background:var(--card);border:1px solid var(--bd);border-radius:12px;overflow:hidden}
  table{width:100%;border-collapse:collapse}
  th,td{text-align:left;padding:9px 14px;border-bottom:1px solid var(--bd);font-size:14px}
  th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
  tbody tr:last-child td{border-bottom:none}
  .srv{color:var(--violet);font-weight:600}
  .dot{font-size:15px} .on{color:var(--accent)} .off{color:#334155}
  tr.tri td{background:rgba(255,77,79,.10)}
  tr.tri .badge-tri{background:#ff4d4f;color:#0a0e14;font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;margin-left:8px}
  .card{background:var(--card);border:1px solid var(--bd);border-left-width:4px;border-radius:10px;padding:14px 16px;margin:11px 0}
  .card .top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .pill{font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px;color:#0a0e14}
  .chip{font-size:11px;color:var(--mut);border:1px solid var(--bd);border-radius:20px;padding:2px 9px}
  .card h3{margin:0;font-size:15px;font-weight:600;flex:1}
  .tgt{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--mut)}
  .card p{margin:9px 0 0;color:#c4cedb}
  .ev{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:var(--mut);background:var(--card2);
      border:1px solid var(--bd);border-radius:6px;padding:7px 10px;margin-top:9px;word-break:break-word}
  .fix{color:#34d399;margin-top:9px}
  .asi{color:var(--mut);font-size:12px;margin-top:9px}
  .conf{display:inline-block;width:64px;height:6px;border-radius:3px;background:#243042;vertical-align:middle;margin-left:6px;overflow:hidden}
  .conf>span{display:block;height:100%;background:var(--accent)}
  .probe .top{display:flex;gap:10px;align-items:center}
  .ok{color:#34d399} .bad{color:#ff4d4f;font-weight:700}
  .allclear{background:var(--card);border:1px solid #14532d;border-radius:12px;padding:22px;color:#34d399;font-weight:600}
  footer{color:var(--mut);font-size:12px;margin-top:36px;border-top:1px solid var(--bd);padding-top:14px}
  a{color:var(--accent);text-decoration:none}
</style></head><body><div class="wrap">

  <header>
    <svg class="logo" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 2v20"/><path d="M5 5v4a7 7 0 0 0 14 0V5"/><path d="M5 5 3 7M19 5l2 2"/><path d="M9 22h6"/>
    </svg>
    <h1>trident<span class="v">v{{ version }}</span></h1>
  </header>
  <div class="tag">MCP security scorecard — OWASP Agentic Top 10 (2026)</div>

  <div class="meta">
    target <code>{{ target_label }}</code> &nbsp;·&nbsp; <b>{{ servers_count }}</b> server{{ '' if servers_count == 1 else 's' }}
    &nbsp;·&nbsp; <b>{{ tools_count }}</b> tools{% if generated_at %} &nbsp;·&nbsp; {{ generated_at }}{% endif %}
  </div>
  {% for n in notes %}<div class="note">⚠ {{ n }}</div>{% endfor %}

  <div class="kpis">
    <div class="kpi"><div class="n">{{ total }}</div><div class="l">Findings</div></div>
    <div class="kpi"><div class="n" style="color:{{ max_color }}">{{ max_sev }}</div><div class="l">Max severity</div></div>
    {% for k in kpi_sev %}<div class="kpi"><div class="n" style="color:{{ k.color }}">{{ k.count }}</div><div class="l">{{ k.label }}</div></div>{% endfor %}
  </div>
  {% if total %}<div class="bar">{% for s in bar %}<span style="width:{{ s.pct }}%;background:{{ s.color }}" title="{{ s.count }} {{ s.label }}"></span>{% endfor %}</div>{% endif %}

  {% if servers %}
  <h2>Capability matrix · Rule of Two</h2>
  <div class="panel"><table>
    <thead><tr><th>Server / tool</th><th>A&nbsp;untrusted</th><th>B&nbsp;sensitive</th><th>C&nbsp;external</th></tr></thead>
    <tbody>
    {% for srv in servers %}
      {% for t in srv.tools %}
      <tr class="{{ 'tri' if t.trifecta }}">
        <td>{% if loop.first %}<span class="srv">{{ srv.name }}</span> / {% else %}<span style="color:#3a4760">↳</span> {% endif %}{{ t.name }}{% if t.trifecta %}<span class="badge-tri">TRIFECTA</span>{% endif %}</td>
        <td class="dot {{ 'on' if t.a else 'off' }}">{{ '●' if t.a else '·' }}</td>
        <td class="dot {{ 'on' if t.b else 'off' }}">{{ '●' if t.b else '·' }}</td>
        <td class="dot {{ 'on' if t.c else 'off' }}">{{ '●' if t.c else '·' }}</td>
      </tr>
      {% endfor %}
    {% endfor %}
    </tbody>
  </table></div>
  {% endif %}

  {% if attempts %}
  <h2>Adaptive probe · attacker moves second</h2>
  {% if canary %}<div class="meta">planted canary <code>{{ canary }}</code></div>{% endif %}
  {% for a in attempts %}
  <div class="card probe" style="border-left-color:{{ '#ff4d4f' if a.breached else '#34d399' }}">
    <div class="top"><span class="chip">{{ a.asi }}</span><h3>{{ a.objective }}</h3>
      <span class="{{ 'bad' if a.breached else 'ok' }}">{{ 'BREACHED' if a.breached else 'withstood' }}</span>
      <span class="chip">{{ a.rounds }} round{{ '' if a.rounds == 1 else 's' }}</span></div>
  </div>
  {% endfor %}
  {% endif %}

  {% if findings %}
  <h2>Findings</h2>
  {% for f in findings %}
  <div class="card" style="border-left-color:{{ f.color }}">
    <div class="top">
      <span class="pill" style="background:{{ f.color }}">{{ f.sev }}</span>
      <h3>{{ f.title }}</h3>
      <span class="chip">{{ f.asi_id }}</span>
      <span class="tgt">{{ f.target }}</span>
    </div>
    <p>{{ f.detail }}</p>
    {% if f.evidence %}<div class="ev">{{ f.evidence }}</div>{% endif %}
    <p class="fix">✓ {{ f.remediation }}</p>
    <p class="asi">{{ f.asi_id }} · {{ f.asi_title }} · confidence {{ f.confidence }}%<span class="conf"><span style="width:{{ f.confidence }}%"></span></span></p>
  </div>
  {% endfor %}
  {% else %}
  <div class="allclear">✓ No findings — this target passed every trident check.</div>
  {% endif %}

  <footer>Generated by <a href="https://github.com/markusweldon/trident">trident</a> ·
    mapped to the <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/">OWASP Top 10 for Agentic Applications (2026)</a></footer>
</div></body></html>"""


def to_html(report: Report) -> str:
    counts = report.severity_counts
    total = len(report.findings)
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

    kpi_sev = [
        {"label": s.value.capitalize(), "count": counts[s], "color": _SEV_COLOR[s]}
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
    ]
    bar = [
        {"label": s.value, "count": counts[s], "color": _SEV_COLOR[s], "pct": round(counts[s] / total * 100, 2)}
        for s in order
        if counts[s]
    ]
    max_sev = report.max_severity
    max_color = _SEV_COLOR[max_sev] if max_sev else "#34d399"

    # Group classified tools by server for the fleet view.
    servers: list[dict] = []
    by_server: dict[str, list] = {}
    for t in report.tools:
        if t.axes is None:
            continue
        by_server.setdefault(t.server, []).append(t)
    for name in sorted(by_server):
        tools = sorted(by_server[name], key=lambda x: (not x.axes.is_trifecta, x.name))
        servers.append(
            {
                "name": name,
                "tools": [
                    {
                        "name": t.name,
                        "a": t.axes.untrusted_input,
                        "b": t.axes.sensitive_access,
                        "c": t.axes.external_comms,
                        "trifecta": t.axes.is_trifecta,
                    }
                    for t in tools
                ],
            }
        )

    attempts = []
    canary = None
    if report.probe:
        canary = report.probe.canary
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
            "asi_id": f.asi.value,
            "asi_title": f.asi.title,
            "confidence": int(round(f.confidence * 100)),
        }
        for f in report.sorted_findings()
    ]

    return Template(_TEMPLATE, autoescape=True).render(
        title=report.target.server_name or report.target.label,
        version=__version__,
        target_label=report.target.label,
        servers_count=len({t.server for t in report.tools}) or len(servers),
        tools_count=len(report.tools),
        generated_at=report.generated_at,
        notes=report.notes,
        total=total,
        max_sev=(max_sev.value.upper() if max_sev else "—"),
        max_color=max_color,
        kpi_sev=kpi_sev,
        bar=bar,
        servers=servers,
        attempts=attempts,
        canary=canary,
        findings=findings,
    )
