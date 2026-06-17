# trident

> Red-team and statically audit MCP servers and AI agents against the **OWASP Top 10 for Agentic Applications (2026)**.

[![CI](https://github.com/markusweldon/trident/actions/workflows/ci.yml/badge.svg)](https://github.com/markusweldon/trident/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP-Agentic%20Top%2010%3A2026-red)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

A basic MCP server is a thin wrapper over an API — and in 2026 there are tens of thousands of them. The hard, unsolved problem isn't *building* one; it's knowing whether the agent that connects to it can be **turned against you**. trident is a security scanner for the agent layer itself.

It does two things no open-source tool does together:

1. **`trident scan`** — statically classifies every tool into the **Lethal Trifecta / Rule-of-Two** axes and flags the dangerous combination, plus tool poisoning, shadowing, unsafe execution, secrets, and unpinned (rug-pull) servers.
2. **`trident probe`** — an **adaptive, "attacker-moves-second"** red-team that drives a live agent against the server and tries to exfiltrate a planted canary, escalating its injections each round.

Every finding maps to an OWASP ASI category and exports to terminal, JSON, and **SARIF** (GitHub code scanning).

---

## Why trident is different

| Tool | Static checks | Adaptive live probing | Lethal-Trifecta / Rule-of-Two | Open source |
|---|:--:|:--:|:--:|:--:|
| Snyk Agent Scan (ex-Invariant `mcp-scan`) | ✓ | ✗ | partial (closed) | source-available |
| MCP-Shield | ✓ | ✗ | ✗ | ✓ |
| garak | targets the LLM | ✓ (LLM endpoint) | ✗ | ✓ |
| promptfoo | eval | ✓ (LLM endpoint) | ✗ | ✓ |
| **trident** | ✓ | ✓ (**live MCP server**) | ✓ | ✓ |

The two open gaps trident fills: a clean **capability-combination** analysis across an agent's whole toolset, and **adaptive injection probing of a live MCP server** (existing dynamic tools aim at the model endpoint, not the MCP tool surface).

---

## Quickstart

```bash
git clone https://github.com/markusweldon/trident && cd trident
uv sync

# Static scan — no API key, never executes the server's tools
uv run trident scan --stdio "npx -y @acme/mcp-server@1.4.2"
uv run trident scan --http https://my-mcp-server.example/mcp --sarif findings.sarif

# Adaptive red-team — requires ANTHROPIC_API_KEY; only run against servers you own
export ANTHROPIC_API_KEY=sk-...
uv run trident probe --stdio "python ./my_server.py" --rounds 4
```

Try it against the bundled deliberately-vulnerable fixture:

```bash
uv run trident scan --stdio "python fixtures/vulnerable/poisoned_server.py"
```

```
╭───────────────────────────────────╮
│ trident — MCP security scan       │
│ server:  acme-devtools   tools: 4 │
╰───────────────────────────────────╯
Capability matrix (Rule of Two)
  Tool                        A  B  C
  acme-devtools:fetch_url     ●  ·  ·
  acme-devtools:read_notes    ·  ●  ·
  acme-devtools:send_report   ·  ·  ●
  acme-devtools:run           ·  ·  ●

  Severity  OWASP   Class                Target                  Title
  HIGH      ASI01   tool_poisoning       acme-devtools:read_notes  Hidden instructions in tool metadata
  HIGH      ASI02   lethal_trifecta      server:acme-devtools      Lethal Trifecta / Rule-of-Two violation
  HIGH      ASI05   unsafe_code_execution acme-devtools:run        Unsafe code/command execution surface
  ...
6 findings  (5 high, 1 medium)
result: FAIL  (--fail-on high)
```

---

## How the signature checks work

### Lethal Trifecta / Rule of Two
Each tool is classified into three axes — **A** ingests untrusted content, **B** touches sensitive data/systems, **C** changes state or communicates externally — using MCP tool annotations (`openWorldHint`, `destructiveHint`, `readOnlyHint`) plus conservative keyword signals. Annotations may only *raise* risk, never clear it (a server's self-declared `readOnlyHint` is attacker-controllable). If a single tool — or the server's combined toolset — spans all three axes, any prompt injection can chain them into exfiltration. That's [Simon Willison's Lethal Trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) and [Meta's Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/).

### Adaptive probe (attacker moves second)
The probe wires the target's tools into a real agent that holds a **planted canary secret**, then an *attacker LLM* crafts an injection — delivered through an untrusted-input tool's output (realistic indirect injection) or the user turn. If the agent doesn't leak the canary through an external-comms tool, the attacker sees the transcript and tries a **stronger, different** payload next round. Success is detected deterministically (canary in a tool call's arguments), so the verdict doesn't depend on a fallible judge. This follows ["The Attacker Moves Second"](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/): static benchmarks overstate robustness; adaptive attacks don't. Tools are never actually executed.

---

## OWASP Agentic Top 10 (2026) coverage

| ASI | Category | trident checks |
|---|---|---|
| ASI01 | Agent Goal Hijack | tool poisoning, adaptive prompt-injection probe |
| ASI02 | Tool Misuse & Exploitation | Lethal Trifecta, canary-exfiltration probe |
| ASI03 | Identity & Privilege Abuse | excessive/wildcard permissions, secrets in config, token passthrough |
| ASI04 | Agentic Supply Chain | tool shadowing, rug-pull / unpinned server |
| ASI05 | Unexpected Code Execution | unsafe code/command-execution surface |
| ASI06–ASI10 | Memory poisoning · inter-agent comms · cascading failures · trust exploitation · rogue agents | roadmap |

v1 focuses on what is observable from a single MCP server; multi-agent categories (ASI07–ASI10) are on the roadmap. See [THREAT_MODEL.md](THREAT_MODEL.md) for the full attack-class → ASI mapping.

---

## Evaluation

**Regression guard (own fixtures).** A labeled corpus (`fixtures/`) of deliberately vulnerable and benign-control servers; CI fails if recall drops or a clean control trips a finding:

```bash
uv run pytest -q -s         # [self-eval] recall=100%  precision=100%  (0 false positives)
```

That proves the detectors don't regress — but it's trident grading its own homework. The real test is tool definitions it *didn't* write:

**Real-world catalog.** [`fixtures/real-world/catalog.json`](fixtures/real-world/catalog.json) holds the published tool specs of popular MCP servers (copied from their docs, never executed). trident's verdicts:

| Server | Axes | Verdict |
|---|:--:|---|
| **GitHub** | A·B·C | 🔴 lethal trifecta — reads issues/PRs (untrusted), reads private repo + secret alerts, creates/pushes/merges |
| filesystem | B·C | 🟡 near-trifecta (reads + writes local files) |
| git | B·C | 🟡 near-trifecta |
| Slack | A·C | 🟡 near-trifecta (reads channel history, posts messages) |
| fetch | A | ✅ clean |
| time | — | ✅ clean |
| memory | C | ✅ clean |

The GitHub verdict matches the real [GitHub MCP exploit](https://invariantlabs.ai/blog/mcp-github-vulnerability) Invariant Labs disclosed — its lethal trifecta is exactly what trident flags, while fetch/time/memory stay quiet.

---

## CI / GitHub Action

Gate pull requests and upload findings to GitHub code scanning:

```yaml
- uses: markusweldon/trident/.github/actions/trident-scan@main
  with:
    stdio: "npx -y @acme/mcp-server@1.4.2"
    fail-on: high
```

`trident scan` exits non-zero when a finding meets `--fail-on`, and `--sarif` output lands in the Security tab.

---

## Architecture

```
src/trident/
├── mcp_client.py        connect (stdio/HTTP) + enumerate tools/resources/prompts
├── taxonomy.py          OWASP ASI01–10, severities, attack classes + metadata
├── models.py            Pydantic: CapabilityAxes, Finding, Report, ProbeReport
├── static/              scan engine: classifier · trifecta · tool_poisoning · shadowing · capabilities
├── dynamic/             probe engine: llm · harness · adaptive (attacker-moves-second)
├── report/              terminal (rich) · sarif
├── scanner.py           static orchestration → Report
└── prober.py            adaptive probe orchestration → Report
```

---

## Ethics

The dynamic probe sends adversarial inputs to a running agent. **Only probe MCP servers you own or are explicitly authorized to test.** trident never executes the target's tools and uses a synthetic canary rather than real secrets. See [ETHICS.md](ETHICS.md).

## References

OWASP Top 10 for Agentic Applications (2026) · [Lethal Trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) · [Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/) · [The Attacker Moves Second](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/) · [MCP Tool Poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)

## License

MIT — see [LICENSE](LICENSE).
