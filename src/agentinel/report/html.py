"""Render a Report as a single self-contained HTML security dashboard (no external assets).

The look follows the Agentinel brand (docs/brand/README.md): Ink background, Sentinel Cyan accent, Space Grotesk and
JetBrains Mono. The fonts are embedded, so a report renders the same offline, attached to a ticket, or on Pages.
"""

from __future__ import annotations

import base64
from functools import cache
from importlib.resources import files

from jinja2 import Template

from .. import __version__
from ..models import Report
from ..taxonomy import Severity

# Severity colours: text on a tint of the same hue, as in the README diagrams.
_SEV = {
    Severity.CRITICAL: ("#FF5C7A", "#3D1520"),
    Severity.HIGH: ("#FF7B72", "#3A1A1C"),
    Severity.MEDIUM: ("#FFBE5C", "#33230B"),
    Severity.LOW: ("#7DB2FF", "#132541"),
    Severity.INFO: ("#A3ADBF", "#1A2130"),
}
_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

_FONTS = [
    ("AgSans", 500, "space-grotesk-latin-500-normal.woff2"),
    ("AgSans", 700, "space-grotesk-latin-700-normal.woff2"),
    ("AgMono", 500, "jetbrains-mono-latin-500-normal.woff2"),
    ("AgMono", 700, "jetbrains-mono-latin-700-normal.woff2"),
]


@cache
def _font_css() -> str:
    """@font-face rules with the brand fonts inlined (SIL OFL 1.1, see report/fonts/)."""
    root = files("agentinel.report") / "fonts"
    rules = []
    for family, weight, name in _FONTS:
        try:
            data = base64.b64encode((root / name).read_bytes()).decode()
        except (FileNotFoundError, OSError):  # fall back to the system stack if fonts weren't packaged
            continue
        rules.append(
            f"@font-face{{font-family:{family};font-weight:{weight};font-display:swap;"
            f"src:url(data:font/woff2;base64,{data}) format('woff2')}}"
        )
    return "".join(rules)


_MARK = (
    '<svg class="mark" viewBox="0 0 64 64" aria-hidden="true"><rect width="64" height="64" rx="17" fill="#22D3EE"/>'
    '<g transform="translate(32 32.6) scale(1.36) translate(-16 -16)" fill="none" stroke="#0A0E16" stroke-linejoin="round">'
    '<path d="M16 2.5 L28 7 V15.5 C28 22.5 22.8 27.2 16 29.5 C9.2 27.2 4 22.5 4 15.5 V7 Z" stroke-width="3.3"/>'
    '<path d="M7.5 16 C11 11.5 21 11.5 24.5 16 C21 20.5 11 20.5 7.5 16 Z" stroke-width="2.5"/>'
    '<circle cx="16" cy="16" r="2.9" fill="#0A0E16" stroke="none"/></g></svg>'
)

_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agentinel · {{ title }}</title>
<style>
  {{ font_css | safe }}
  :root{
    color-scheme:dark;
    --ink:#0A0E16; --panel:#0F141F; --raised:#141B28; --line:#232D3F; --frame:#1C2433;
    --text:#F2F5FA; --muted:#A3ADBF; --faint:#6C7689;
    --cyan:#22D3EE; --cyan-tint:#0B2A33;
    --a:#7DB2FF; --a-tint:#132541; --b:#FFBE5C; --b-tint:#33230B; --c:#FF7B72; --c-tint:#3A1A1C;
    --violet:#BFA2FF; --ok:#22D3EE;
    --sans:AgSans,"Space Grotesk",-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
    --mono:AgMono,"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  }
  *{box-sizing:border-box}
  html{background:var(--ink)}
  body{margin:0;color:var(--text);font:500 15px/1.55 var(--sans);-webkit-font-smoothing:antialiased;
       background:
         radial-gradient(900px 480px at 92% -8%, rgba(34,211,238,.10), transparent 70%),
         radial-gradient(circle at 1.5px 1.5px, #182030 1.1px, transparent 1.3px) 0 0/22px 22px,
         var(--ink)}
  .wrap{max-width:1080px;margin:0 auto;padding:40px 24px 72px}
  a{color:var(--cyan);text-decoration:none} a:hover{text-decoration:underline}
  code,.mono{font-family:var(--mono);font-weight:500}

  /* header */
  header{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
  .mark{width:46px;height:46px;flex:none}
  .brand{flex:1;min-width:240px}
  .eyebrow{line-height:1.4;font:700 12px/1.4 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--text)}
  .eyebrow span{color:var(--faint);font-weight:500}
  h1{margin:6px 0 0;font:700 28px/1.15 var(--sans);letter-spacing:-.02em;word-break:break-word}
  .verdict{font:700 12px/1 var(--mono);letter-spacing:.12em;padding:9px 14px;border-radius:999px;white-space:nowrap}
  .verdict.fail{color:var(--c);background:var(--c-tint)} .verdict.pass{color:var(--cyan);background:var(--cyan-tint)}
  .meta{display:flex;flex-wrap:wrap;gap:8px;margin:20px 0 0}
  .meta span{max-width:100%;overflow-wrap:anywhere;font:500 12.5px/1.3 var(--mono);color:var(--muted);background:var(--panel);border:1px solid var(--line);
             border-radius:8px;padding:8px 10px}
  .meta b{color:var(--text);font-weight:700}
  .note{margin:12px 0 0;padding:10px 14px;border-radius:10px;background:var(--b-tint);color:var(--b);font-size:13.5px}

  /* sections */
  section{margin-top:30px}
  h2{display:flex;align-items:center;gap:10px;margin:0 0 12px;font:700 12px/1 var(--mono);letter-spacing:.14em;
     text-transform:uppercase;color:var(--muted)}
  h2 small{font:500 12px/1 var(--mono);letter-spacing:0;text-transform:none;color:var(--faint)}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:16px;position:relative}
  .card.accent:before{content:"";position:absolute;left:18px;right:18px;top:-1px;height:3px;border-radius:2px;background:var(--accent,var(--cyan))}

  /* summary */
  .summary{display:grid;grid-template-columns:1.1fr 1fr;gap:16px}
  .summary>*{min-width:0}
  @media (max-width:820px){.summary{grid-template-columns:1fr}}
  .kpis{padding:20px 22px}
  .kpirow{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
  @media (max-width:520px){.kpirow{grid-template-columns:repeat(2,minmax(0,1fr));row-gap:18px}}
  .kpi .n{font:700 34px/1 var(--sans);letter-spacing:-.02em}
  .kpi .l{margin-top:8px;font:500 11.5px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--faint)}
  .bar{display:flex;height:8px;border-radius:6px;overflow:hidden;margin-top:20px;background:var(--raised)}
  .bar span{display:block;height:100%}
  .legend{display:flex;flex-wrap:wrap;gap:14px;margin-top:10px;font:500 12px/1 var(--mono);color:var(--muted)}
  .legend i{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px;vertical-align:0}
  .asi{margin-top:20px;padding-top:16px;border-top:1px solid var(--line)}
  .asi h4{margin:0 0 10px;font:700 11.5px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--faint)}
  .asirow{display:flex;align-items:center;gap:10px;padding:5px 0;font-size:14px}
  .asirow .id{font:700 11.5px/1 var(--mono);color:var(--cyan);background:var(--cyan-tint);border-radius:6px;padding:5px 7px}
  .asirow .t{flex:1} .asirow .n{font:700 13px/1 var(--mono);color:var(--muted)}
  .asi .none{color:var(--faint);font-size:13.5px}

  .axes{padding:20px 22px}
  .axes .head{display:flex;justify-content:space-between;align-items:baseline;gap:10px;margin-bottom:14px}
  .axes .head b{font-size:16px}
  .axis{display:flex;align-items:center;gap:12px;padding:9px 0;border-top:1px solid var(--line)}
  .axis:first-of-type{border-top:none}
  .letter{width:28px;height:28px;border-radius:8px;display:grid;place-items:center;font:700 14px/1 var(--mono);flex:none}
  .axis .what{flex:1} .axis .what small{display:block;color:var(--faint);font-size:12.5px}
  .axis .count{font:700 13px/1 var(--mono);color:var(--muted)}
  .axis.off .letter{background:var(--raised)!important;color:var(--faint)!important} .axis.off .what{color:var(--faint)}
  .tri-alert{margin-top:14px;padding:12px 14px;border-radius:12px;background:var(--c-tint);color:var(--text);font-size:13.5px;border:1px solid rgba(255,123,114,.35)}
  .tri-alert b{color:var(--c)}
  .tri-ok{margin-top:14px;padding:12px 14px;border-radius:12px;background:var(--cyan-tint);color:var(--text);font-size:13.5px}
  .tri-ok b{color:var(--cyan)}

  /* matrix */
  .matrix{overflow-x:auto}
  table{width:100%;border-collapse:collapse;min-width:560px}
  th,td{padding:11px 16px;text-align:left;border-top:1px solid var(--line)}
  thead th{border-top:none;font:500 11.5px/1.3 var(--mono);letter-spacing:.06em;color:var(--faint);vertical-align:bottom}
  thead th.ax{text-align:center;width:118px}
  thead th.ax b{display:block;font-size:14px;margin-bottom:4px}
  td.ax{text-align:center}
  tr.srv td{background:rgba(20,27,40,.6);font:700 13px/1 var(--mono);color:var(--violet);padding-top:12px;padding-bottom:12px}
  tr.srv td small{color:var(--faint);font-weight:500;margin-left:8px}
  td.tool{font:500 14px/1.3 var(--mono)}
  .dot{display:inline-block;width:16px;height:16px;border-radius:50%;vertical-align:middle;position:relative}
  .dot.on:after{content:"";position:absolute;inset:4px;border-radius:50%;background:currentColor}
  .dot.on{border:1.5px solid currentColor}
  .dot.off{width:6px;height:6px;background:var(--line)}
  tr.tri td{background:rgba(255,123,114,.07)}
  .tag{display:inline-block;margin-left:10px;padding:3px 8px;border-radius:6px;font:700 10.5px/1 var(--mono);letter-spacing:.1em;
       color:var(--c);background:var(--c-tint);vertical-align:1px}

  /* filters */
  .filters{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 12px}
  .filters button{font:700 11.5px/1 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);
                  background:var(--panel);border:1px solid var(--line);border-radius:999px;padding:8px 12px;cursor:pointer}
  .filters button.on{color:var(--ink);background:var(--cyan);border-color:var(--cyan)}
  .filters button:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}

  /* findings */
  .finding{padding:18px 22px 18px 24px;margin-top:12px;border-radius:14px;background:var(--panel);border:1px solid var(--line);position:relative}
  .finding:before{content:"";position:absolute;left:-1px;top:14px;bottom:14px;width:4px;border-radius:2px;background:var(--sev)}
  .finding .top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .sev{font:700 11px/1 var(--mono);letter-spacing:.12em;padding:6px 10px;border-radius:999px;color:var(--sev);background:var(--sev-tint)}
  .finding h3{margin:0;flex:1;min-width:220px;font:700 17px/1.3 var(--sans);letter-spacing:-.01em}
  .chip{font:700 11.5px/1 var(--mono);color:var(--muted);background:var(--raised);border-radius:6px;padding:6px 8px}
  .target{font:500 12.5px/1.4 var(--mono);color:var(--faint);margin-top:8px;word-break:break-all}
  .finding p{margin:10px 0 0;color:#CBD3E1}
  .evidence{margin-top:12px;padding:10px 12px;border-radius:10px;background:var(--ink);border:1px solid var(--line);
            font:500 12.5px/1.5 var(--mono);color:var(--muted);white-space:pre-wrap;word-break:break-word}
  .evidence:before{content:"evidence";display:block;font-weight:700;font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--faint);margin-bottom:4px}
  .fix{display:flex;gap:10px;margin-top:12px;padding:12px 14px;border-radius:10px;background:var(--cyan-tint);color:var(--text);font-size:14px}
  .fix svg{flex:none;margin-top:2px}
  .foot{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:12px;font:500 12px/1 var(--mono);color:var(--faint)}
  .conf{width:72px;height:5px;border-radius:3px;background:var(--raised);overflow:hidden}
  .conf span{display:block;height:100%;background:var(--cyan)}

  /* probe */
  .attempt{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:14px 18px;margin-top:10px;border-radius:12px;background:var(--panel);border:1px solid var(--line)}
  .attempt h3{flex:1;margin:0;font:700 15px/1.3 var(--sans)}
  .breached{color:var(--c);background:var(--c-tint)} .withstood{color:var(--cyan);background:var(--cyan-tint)}

  .allclear{display:flex;align-items:center;gap:16px;padding:22px 24px;border-radius:16px;background:var(--cyan-tint);border:1px solid rgba(34,211,238,.35)}
  .allclear b{display:block;font-size:18px} .allclear span{color:var(--muted)}

  footer{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:44px;padding-top:18px;border-top:1px solid var(--line);color:var(--faint);font-size:13px}
  footer .mark{width:22px;height:22px}
  footer .sp{flex:1}
  @media (max-width:520px){.wrap{padding:28px 16px 56px}h1{font-size:23px}.kpis,.axes{padding:18px 16px}.finding{padding:16px 16px 16px 18px}th,td{padding:10px 12px}}
  @media print{body{background:#fff;color:#000}.filters{display:none}}
</style></head><body><div class="wrap">

  <header>
    {{ mark | safe }}
    <div class="brand">
      <div class="eyebrow">Agentinel <span>/ {{ 'Probe' if attempts and not servers else 'MCP security scan' }} · v{{ version }}</span></div>
      <h1>{{ title }}</h1>
    </div>
    <div class="verdict {{ 'fail' if failing else 'pass' }}">{{ verdict }}</div>
  </header>

  <div class="meta">
    {% if target_label != title %}<span>target <b>{{ target_label }}</b></span>{% endif %}
    <span><b>{{ servers_count }}</b> server{{ '' if servers_count == 1 else 's' }}</span>
    <span><b>{{ tools_count }}</b> tool{{ '' if tools_count == 1 else 's' }}</span>
    {% if generated_at %}<span>{{ generated_at }}</span>{% endif %}
  </div>
  {% for n in notes %}<div class="note">{{ n }}</div>{% endfor %}

  <section class="summary">
    <div class="card kpis">
      <h2>Findings</h2>
      <div class="kpirow">
        <div class="kpi"><div class="n">{{ total }}</div><div class="l">Total</div></div>
        {% for k in kpi_sev %}<div class="kpi"><div class="n" style="color:{{ k.color if k.count else 'var(--faint)' }}">{{ k.count }}</div><div class="l">{{ k.label }}</div></div>{% endfor %}
      </div>
      {% if total %}
      <div class="bar">{% for s in bar %}<span style="width:{{ s.pct }}%;background:{{ s.color }}" title="{{ s.count }} {{ s.label }}"></span>{% endfor %}</div>
      <div class="legend">{% for s in bar %}<span><i style="background:{{ s.color }}"></i>{{ s.count }} {{ s.label }}</span>{% endfor %}</div>
      {% endif %}
      <div class="asi">
        <h4>By OWASP Agentic category</h4>
        {% for c in asi %}<div class="asirow"><span class="id">{{ c.id }}</span><span class="t">{{ c.title }}</span><span class="n">{{ c.count }}</span></div>
        {% else %}<div class="none">Nothing found in any OWASP Agentic Top 10 category.</div>{% endfor %}
      </div>
    </div>

    {% if servers %}
    <div class="card axes">
      <div class="head"><h2 style="margin:0">Lethal trifecta</h2><small class="mono" style="color:var(--faint)">Rule of Two</small></div>
      {% for ax in axes %}
      <div class="axis {{ '' if ax.count else 'off' }}">
        <div class="letter" style="color:var(--{{ ax.key }});background:var(--{{ ax.key }}-tint)">{{ ax.letter }}</div>
        <div class="what">{{ ax.label }}<small>{{ ax.hint }}</small></div>
        <div class="count">{{ ax.count }} tool{{ '' if ax.count == 1 else 's' }}</div>
      </div>
      {% endfor %}
      {% if fleet_trifecta %}
      <div class="tri-alert"><b>All three axes are present.</b> A prompt injection through one tool can be chained into reading sensitive data and sending it out.</div>
      {% else %}
      <div class="tri-ok"><b>Trifecta broken.</b> {{ axes_present }} of 3 axes present, so an injection can't complete an exfiltration path on its own.</div>
      {% endif %}
    </div>
    {% endif %}
  </section>

  {% if servers %}
  <section>
    <h2>Capability matrix <small>· Rule of Two</small></h2>
    <div class="card matrix"><table>
      <thead><tr><th>Server / tool</th>
        <th class="ax" style="color:var(--a)"><b>A</b>untrusted input</th>
        <th class="ax" style="color:var(--b)"><b>B</b>sensitive data</th>
        <th class="ax" style="color:var(--c)"><b>C</b>external action</th></tr></thead>
      <tbody>
      {% for srv in servers %}
        <tr class="srv"><td colspan="4">{{ srv.name }}<small>{{ srv.tools|length }} tool{{ '' if srv.tools|length == 1 else 's' }}</small></td></tr>
        {% for t in srv.tools %}
        <tr class="{{ 'tri' if t.trifecta }}">
          <td class="tool">{{ t.name }}{% if t.trifecta %}<span class="tag">TRIFECTA</span>{% endif %}</td>
          <td class="ax"><span class="dot {{ 'on' if t.a else 'off' }}" style="color:var(--a)" title="{{ 'untrusted input' if t.a else '' }}"></span></td>
          <td class="ax"><span class="dot {{ 'on' if t.b else 'off' }}" style="color:var(--b)" title="{{ 'sensitive data' if t.b else '' }}"></span></td>
          <td class="ax"><span class="dot {{ 'on' if t.c else 'off' }}" style="color:var(--c)" title="{{ 'external action' if t.c else '' }}"></span></td>
        </tr>
        {% endfor %}
      {% endfor %}
      </tbody>
    </table></div>
  </section>
  {% endif %}

  {% if attempts %}
  <section>
    <h2>Adaptive probe <small>· attacker moves second</small></h2>
    {% if canary %}<div class="meta" style="margin:0 0 4px"><span>planted canary <b>{{ canary }}</b></span></div>{% endif %}
    {% for a in attempts %}
    <div class="attempt">
      <span class="chip">{{ a.asi }}</span><h3>{{ a.objective }}</h3>
      <span class="sev {{ 'breached' if a.breached else 'withstood' }}">{{ 'BREACHED' if a.breached else 'WITHSTOOD' }}</span>
      <span class="chip">{{ a.rounds }} round{{ '' if a.rounds == 1 else 's' }}</span>
    </div>
    {% endfor %}
  </section>
  {% endif %}

  <section>
  {% if findings %}
    <h2>Findings <small>· most severe first</small></h2>
    {% if sev_filters|length > 1 %}
    <div class="filters" role="group" aria-label="Filter findings by severity">
      <button class="on" data-sev="all">All · {{ total }}</button>
      {% for s in sev_filters %}<button data-sev="{{ s.key }}">{{ s.label }} · {{ s.count }}</button>{% endfor %}
    </div>
    {% endif %}
    {% for f in findings %}
    <article class="finding" data-sev="{{ f.key }}" style="--sev:{{ f.color }};--sev-tint:{{ f.tint }}">
      <div class="top">
        <span class="sev">{{ f.sev }}</span>
        <h3>{{ f.title }}</h3>
        <span class="chip">{{ f.asi_id }}</span>
      </div>
      <div class="target">{{ f.target }}</div>
      <p>{{ f.detail }}</p>
      {% if f.evidence %}<div class="evidence">{{ f.evidence }}</div>{% endif %}
      <div class="fix"><svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="#22D3EE" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.5 L6.5 12 L13 4.5"/></svg><span>{{ f.remediation }}</span></div>
      <div class="foot"><span>{{ f.asi_id }} · {{ f.asi_title }}</span><span>confidence {{ f.confidence }}%</span><span class="conf"><span style="width:{{ f.confidence }}%"></span></span></div>
    </article>
    {% endfor %}
  {% else %}
    <div class="allclear">
      <svg width="34" height="34" viewBox="0 0 34 34" fill="none"><circle cx="17" cy="17" r="16" fill="#0B2A33" stroke="#22D3EE" stroke-width="1.5"/><path d="M10 17.5 L15 22 L24.5 12" stroke="#22D3EE" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>
      <div><b>No findings</b><span>This target passed every Agentinel check.</span></div>
    </div>
  {% endif %}
  </section>

  <footer>
    {{ mark | safe }}
    <span>Generated by <a href="https://github.com/markusweldon/agentinel">Agentinel</a> v{{ version }}. Reads tool metadata only and never calls a tool.</span>
    <span class="sp"></span>
    <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/">OWASP Agentic Top 10 (2026)</a>
  </footer>
</div>
<script>
  (function () {
    var buttons = document.querySelectorAll(".filters button");
    buttons.forEach(function (b) {
      b.addEventListener("click", function () {
        buttons.forEach(function (x) { x.classList.toggle("on", x === b); });
        document.querySelectorAll(".finding").forEach(function (f) {
          f.style.display = b.dataset.sev === "all" || f.dataset.sev === b.dataset.sev ? "" : "none";
        });
      });
    });
  })();
</script>
</body></html>"""


def to_html(report: Report) -> str:
    counts = report.severity_counts
    total = len(report.findings)

    kpi_sev = [
        {"label": s.value.capitalize(), "count": counts[s], "color": _SEV[s][0]}
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
    ]
    bar = [
        {"label": s.value, "count": counts[s], "color": _SEV[s][0], "pct": round(counts[s] / total * 100, 2)}
        for s in _ORDER
        if counts[s]
    ]
    sev_filters = [{"key": s.value, "label": s.value, "count": counts[s]} for s in _ORDER if counts[s]]

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

    # How many classified tools sit on each axis, across the whole target (one server or a fleet).
    classified = [t for srv in servers for t in srv["tools"]]
    axes = [
        {
            "key": "a",
            "letter": "A",
            "label": "Untrusted input",
            "hint": "reads content an attacker can write",
            "count": sum(t["a"] for t in classified),
        },
        {
            "key": "b",
            "letter": "B",
            "label": "Sensitive data",
            "hint": "reaches private data or systems",
            "count": sum(t["b"] for t in classified),
        },
        {
            "key": "c",
            "letter": "C",
            "label": "External action",
            "hint": "changes state or sends data out",
            "count": sum(t["c"] for t in classified),
        },
    ]
    axes_present = sum(1 for ax in axes if ax["count"])

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
            "key": f.severity.value,
            "sev": f.severity.value.upper(),
            "color": _SEV[f.severity][0],
            "tint": _SEV[f.severity][1],
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

    asi = [
        {"id": cat.value, "title": cat.title, "count": n}
        for cat, n in sorted(report.asi_counts.items(), key=lambda kv: kv[0].value)
        if n
    ]

    max_sev = report.max_severity
    breached = any(a["breached"] for a in attempts)
    failing = bool(max_sev and max_sev.rank >= Severity.HIGH.rank) or breached
    if failing:
        worst = sum(1 for f in report.findings if f.severity == max_sev) if max_sev else 0
        verdict = f"FAIL · {worst} {max_sev.value}" if max_sev else "FAIL · BREACHED"
    elif total:
        verdict = f"REVIEW · {total} finding{'' if total == 1 else 's'}"
    else:
        verdict = "PASS · ALL CLEAR"

    return Template(_TEMPLATE, autoescape=True).render(
        font_css=_font_css(),
        mark=_MARK,
        title=report.target.server_name or report.target.label,
        version=__version__,
        target_label=report.target.label,
        servers_count=len({t.server for t in report.tools}) or len(servers),
        tools_count=len(report.tools),
        generated_at=report.generated_at,
        notes=report.notes,
        total=total,
        kpi_sev=kpi_sev,
        bar=bar,
        sev_filters=sev_filters,
        servers=servers,
        axes=axes,
        axes_present=axes_present,
        fleet_trifecta=axes_present == 3,
        attempts=attempts,
        canary=canary,
        findings=findings,
        asi=asi,
        failing=failing,
        verdict=verdict,
    )
