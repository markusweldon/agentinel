# Changelog

All notable changes to Agentinel are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] — unreleased

First public release: an open-source auditor for MCP servers and agent fleets.

### Added
- **`agentinel scan`** — static Rule-of-Two / lethal-trifecta analysis, per-server **and** across a
  whole fleet, plus tool poisoning, secrets in config, unsafe code-/CLI-command-execution surfaces,
  over-broad permissions, cross-server name shadowing, and rug-pull drift — each mapped to the
  OWASP Agentic Top 10 (2026).
- **`agentinel probe`** — an experimental, adaptive "attacker-moves-second" prompt-injection probe
  running both goal-hijack and canary-exfiltration objectives. (Unit-tested with a scripted model;
  not yet validated against a live model.)
- Outputs: rich terminal, JSON, **SARIF** (GitHub code scanning), and a self-contained **HTML dashboard**.
- **`agentinel-mcp`** — a read-only MCP server exposing a single `assess_tools` tool.
- A GitHub Action, a Pages-hosted demo, and a **35-server** real-world eval catalog.
- A capability-surface study of those 35 servers ([RESEARCH.md](RESEARCH.md)), reproducible via
  `scripts/analyze_catalog.py`.

### Fixed (post-audit hardening)
- Ordinary read + write servers no longer produce a false HIGH lethal-trifecta (write-tool read-gate).
- camelCase acronyms (e.g. `getAPIKey`) are split correctly for capability matching.
- Legitimate emoji (U+200D ZWJ) and ordinary tool docs no longer trip tool-poisoning detection.
- Rug-pull drift now fingerprints tool **annotations**, so a `readOnlyHint`/`destructiveHint` flip is caught.
- Tool-poisoning now scans **resource and prompt** descriptions, not only tool metadata.
- `--config` scans inherit and merge the process environment and expand `${VAR}`, so servers that
  declare an API key launch correctly.
- Shadowing no longer false-fires on "When the user…" plus generic tool names.

[0.1.0]: https://github.com/markusweldon/agentinel
