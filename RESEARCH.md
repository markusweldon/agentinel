# The MCP capability surface: auditing 35 popular servers

*An aggregate look at the lethal-trifecta exposure of widely-used MCP servers, produced with
[Agentinel](https://github.com/markusweldon/agentinel)'s static engine. Reproducible — see the end.*

## TL;DR

I ran Agentinel's static analyzer over the **published tool specs of 35 popular MCP servers**
(184 tools total). No server was executed; this reads tool *metadata* only. Mapping each tool to
the three lethal-trifecta axes — **A** untrusted input · **B** sensitive data · **C** external
comms / state change — the picture is:

| Verdict | Servers | Share |
|---|--:|--:|
| 🔴 Full single-server lethal trifecta (A + B + C) | 2 | ~6% |
| 🟠 Arbitrary code-execution surface | 4 | ~11% |
| 🟡 Near-trifecta (two of three axes) | 13 | ~37% |
| ✅ Clean (one axis or none) | 16 | ~46% |

**~46% of these servers already span at least two of the three axes.** That's the headline: not
that any server is "hacked," but that the *combination* which makes prompt injection dangerous is
one server — or one careless pairing of servers — away for a large share of the ecosystem.

## What this measures — and what it does not

**This measures capability surface, not vulnerabilities.** A code-execution tool is not a bug — it
is the entire point of a sandbox server like e2b. Reading web pages is the point of a search
server. None of these servers is "insecure" for having capabilities.

The risk the lethal trifecta describes is *emergent*: an agent that can (A) ingest untrusted
content, (B) reach sensitive data, and (C) send data out can be turned against its user by a single
prompt injection — because the attacker's instructions ride in on axis A and leave through axis C.
So the useful question isn't "is this server vulnerable?" It's **"what capability does connecting
this server hand my agent, and does the combination cross the line?"** That's what these numbers
map.

## Method

- **Source.** Tool names + one-line descriptions copied from each server's published docs/READMEs
  (see [`fixtures/real-world/catalog.json`](fixtures/real-world/catalog.json)). Descriptions were
  lightly trimmed to the factual capability; no risk language was added.
- **Engine.** Agentinel's static classifier assigns each tool to axes A/B/C from conservative
  keyword signals + MCP annotations, then flags a lethal trifecta (per-server or across a fleet),
  tool poisoning, unsafe code execution, secrets, and over-broad permissions.
- **No execution.** Nothing is launched or called — `analyze()` runs over in-memory metadata.
- **Sample.** 35 servers across code hosts, databases, cloud/infra, browser automation, code
  sandboxes, search/scraping, productivity/SaaS, and communication.

## What stood out

- **Full trifecta in one server (2):** GitHub and Notion. Both *read* untrusted user content
  (issues/PRs, comments/databases), *hold* sensitive data, and *write/communicate*. GitHub's case
  matches a [real-world exploit disclosed in the wild](https://invariantlabs.ai/blog/mcp-github-vulnerability).
- **Arbitrary code / command execution (4):** e2b (`run_code`), AWS (`call_aws` — arbitrary CLI),
  Kubernetes (`kubectl_generic`), Puppeteer (`evaluate` — arbitrary JavaScript). Legitimate by
  design, and the single highest-impact capability to gate behind human approval.
- **The near-trifecta middle (13):** databases (sqlite, mongodb), infra (docker, grafana), and
  SaaS (linear, jira, confluence, discord, …) that read user content **and** write — one added
  capability (or one co-installed server) away from the full trifecta.
- **Genuinely clean (16):** read-only or single-axis servers — search/scrapers (brave, exa,
  firecrawl), a key-value store (redis), maps, calendars. Agentinel stays quiet on these, which is
  the point: a detector that flags everything is useless.

## Why it matters: the *accidental* trifecta

Most individual servers are scoped and fine. The danger usually shows up when you **combine** them:
a web-fetch server (A) + a filesystem server (B) + a Slack server (C), each installed for a good
reason, together hand one agent the full trifecta — a path nobody designed and nobody reviewed.
Agentinel flags that cross-server combination, and [Meta's Rule of
Two](https://ai.meta.com/blog/practical-ai-agent-security/) is the mitigation: don't let one agent
hold all three axes without a human in the loop.

## Honest limitations

- **Heuristic.** The classifier is keyword-based; it under-tags some servers (e.g. CI/CD "trigger a
  pipeline" tools read as benign) and could over-tag others. `--llm-classify` sharpens borderline
  calls. These numbers are a *signal*, not an audit certificate.
- **Small, opinionated sample.** N = 35, chosen for popularity/recognizability, not sampled
  randomly. Some entries are community implementations or archived/deprecated servers (noted in the
  catalog); tool sets are capped at ~7 per server, prioritizing security-relevant tools.
- **Static only.** This reasons about the capability surface. Whether an agent *actually* leaks
  under injection is what the (experimental) dynamic probe is for.
- **Capability ≠ vulnerability**, restated because it matters: nothing here is a disclosure of a
  flaw in any server.

## Responsible disclosure

Nothing in this post is a vulnerability report. It describes documented, intended capabilities and
the *design-time* risk of combining them. No server is named as insecure; no exploit is published.
If future dynamic testing ever surfaces a genuine flaw in a specific server, it will follow
coordinated disclosure (see [ETHICS.md](ETHICS.md)) before any public writeup.

## Reproduce it

```bash
git clone https://github.com/markusweldon/agentinel && cd agentinel
uv sync
uv run python scripts/analyze_catalog.py
```
