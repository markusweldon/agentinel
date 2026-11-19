# Agentinel brand

The README logo, hero, trifecta diagram and social preview are generated from one script, so they stay consistent.

```bash
uv run --with fonttools --with brotli python docs/brand/build.py          # SVGs in docs/assets/
uv run --with fonttools --with brotli --with playwright \
  python docs/brand/build.py --png                                        # + social-preview.png
```

Edit `build.py` and rerun it; don't hand-edit the SVGs in `docs/assets/`.

Agentinel is a sibling of [OpenFix](https://github.com/markusweldon/openfix) and shares its design system: the Ink
background, the same type, dark cards with a dot grid, and dark-only images. Each project has its own signal colour.

## Mark

A shield with a watching eye: a sentinel that sees what your agents can reach.

| Use | File |
| --- | --- |
| README logo | `docs/assets/logo.svg` (cyan tile, Ink glyph, on a dark card) |
| Icon, avatar, favicon | `docs/assets/mark.svg` |
| GitHub social preview (Settings → General → Social preview) | `docs/assets/social-preview.png` |

Keep at least a quarter of the tile's width clear around the mark. Don't recolour it, outline it or put it on a busy image.

## Colour

| Token | Hex | Use |
| --- | --- | --- |
| Sentinel Cyan | `#22D3EE` | The brand colour. Means *watching*. Mark tile, highlights, headline accents. |
| Ink | `#0A0E16` | Backgrounds, and the mark's glyph on cyan. Shared with OpenFix. |
| Blue | `#7DB2FF` | Axis A, untrusted input. |
| Amber | `#FFBE5C` | Axis B, sensitive data. |
| Red | `#FF7B72` | Axis C, external action, and high-severity findings. |
| Violet | `#BFA2FF` | Server names. |

OpenFix's Signal Lime (`#C6F432`, *verified*) belongs to OpenFix; don't use it here.

## Type

- **Space Grotesk** (400, 500, 700) for headings and labels.
- **JetBrains Mono** (500, 700) for commands, tool names, eyebrows and pills.

Both are under the SIL Open Font License 1.1 (`fonts/OFL-*.txt`). The SVGs embed a subset of each, so they render the same
everywhere, including GitHub's image sandbox.

## Voice

Plain and specific. Name the capability and the risk ("reads untrusted issues and PRs, and can push and merge"), and
say what was checked, not how clever it was.
