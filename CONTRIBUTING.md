# Contributing to Agentinel

Thanks for helping make AI-agent setups safer. Agentinel is an open, educational tool — contributions that add real-world coverage or sharpen detection are especially welcome.

## Dev setup

```bash
git clone https://github.com/markusweldon/agentinel && cd agentinel
uv sync
uv run pytest -q          # tests (incl. the self-eval + real-world catalog)
uv run ruff check src tests && uv run ruff format --check src tests
uv run mypy src
```

CI runs all four (lint, format, types, tests) on every PR. Keep them green.

## Two most common contributions

### 1. Add a real-world server to the catalog

The real-world catalog ([`fixtures/real-world/catalog.json`](fixtures/real-world/catalog.json)) is how we check Agentinel against tool definitions it didn't author. To add one:

1. Copy the server's tool **names + one-line descriptions from its published docs** (do **not** run it — the catalog is metadata only).
2. Add an entry: `"servername": [ {"name": "...", "description": "..."}, ... ]`.
3. Add an assertion in [`tests/test_real_world.py`](tests/test_real_world.py) for the expected verdict — pick the right group:
   - full trifecta (HIGH) — reads untrusted content **and** sensitive data **and** writes/communicates;
   - near-trifecta (INFO) — two of the three axes;
   - code execution — exposes a "run/eval arbitrary X" tool;
   - benign — one axis or none, no actionable findings.
4. `uv run pytest -q`. If the verdict is wrong, you've likely found a detector gap — fix it (below) rather than weakening the assertion.

Real servers regularly surface false positives/negatives — that's the point. Each one makes the detectors better.

### 2. Add or improve a detector

Static detectors live in [`src/agentinel/static/`](src/agentinel/static/). Each is a function `check_*(snapshot) -> list[Finding]` (or `(snapshots)` for cross-server checks), registered in `static/__init__.py:run_detectors`.

To add a new finding type:
1. Add an `AttackClass` member + an `AttackInfo` (title, ASI category, default severity, remediation, references) in [`taxonomy.py`](src/agentinel/taxonomy.py).
2. Write the detector in `static/`, emitting `Finding.from_attack(...)`.
3. Register it in `run_detectors`.
4. Add a deliberately-vulnerable fixture under `fixtures/vulnerable/` **and** a benign control under `fixtures/clean/`, then a test. The clean control matters as much as the vulnerable one — a detector that false-positives is worse than none.

Capability classification (the A/B/C axes) lives in `static/classifier.py`. Prefer precise, low-false-positive keywords; if a term is ambiguous (e.g. "execute"), gate it with context.

## Ground rules

- **Style:** ruff (line length 120) + mypy clean. Match the surrounding code.
- **No real secrets** in fixtures or tests — build dummy tokens at runtime so the repo scans clean.
- **The probe only targets what you own.** Don't add code that executes a target's real tools, and don't point the probe at third-party servers. See [ETHICS.md](ETHICS.md).
- **Keep claims honest.** This is a heuristic v0.1 that operationalizes known concepts (Lethal Trifecta, Rule of Two, OWASP Agentic Top 10) — describe findings as signals, not guarantees.

## PRs

Small, focused PRs with tests. Describe what you changed and why; if you fixed a detector, mention the real server/case that exposed it.
