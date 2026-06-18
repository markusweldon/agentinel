# Threat model

agentinel assesses the security of an **MCP server and the agent that connects to it**. This document records the trust boundaries, the attack classes agentinel detects, and how each maps to the OWASP Top 10 for Agentic Applications (2026).

## Trust model

- **Untrusted:** everything the server declares — tool names, descriptions, parameter docs, JSON schemas, tool annotations (`readOnlyHint`, etc.), server instructions, and any content returned by a tool. All of it reaches the model and can carry instructions.
- **Assumption:** the agent is a capable LLM that follows instructions found in tool metadata and tool output unless specifically defended. This is the realistic 2026 baseline.
- **Out of scope (v1):** network/transport security, server-side RCE in the server's own implementation, and multi-agent (A2A) topologies. agentinel reasons about what the *agent* can be made to do, not the server's internal bugs.

## Attack classes → OWASP ASI

| Attack class | What agentinel looks for | Detection | OWASP ASI |
|---|---|---|---|
| Tool poisoning | Hidden instructions in tool/param descriptions or server instructions: invisible/bidi Unicode, instruction-override and concealment phrasing, references to credential files | static | ASI01 |
| Prompt injection (live) | Agent steered off-task by an adaptive injection | dynamic probe | ASI01 |
| Lethal Trifecta / Rule-of-Two | A single tool, or the server's combined toolset, holds untrusted-input **and** sensitive-access **and** external-comms | static | ASI02 |
| Data exfiltration (live) | Agent induced to leak a planted canary through an external-comms tool | dynamic probe | ASI02 |
| Excessive permissions | Over-broad / wildcard scope advertised by a tool | static | ASI03 |
| Secrets exposure | API keys / tokens / basic-auth creds embedded in the launch command | static | ASI03 |
| Token passthrough | Server reuses/forwards a token across a trust boundary (confused deputy) | taxonomy / roadmap | ASI03 |
| Tool shadowing | Same tool name across servers, or cross-tool reference with manipulative phrasing | static | ASI04 |
| Rug pull / unpinned | Server launched from a mutable ref (`latest`, unpinned `npx`/`uvx`) so tool definitions can change after approval | static | ASI04 |
| Unsafe code execution | Tool exposes shell/eval/command execution to the agent | static | ASI05 |

## Capability classification (Rule of Two)

Each tool is assigned to zero or more axes:

- **A — untrusted input:** fetches/reads external or third-party content (web, email, issues, RSS, …) or has `openWorldHint=true`.
- **B — sensitive access:** reads files, databases, secrets, cloud, customer/PII data.
- **C — external comms / state change:** sends, posts, writes, deploys, executes; or `destructiveHint=true` / `readOnlyHint=false`.

Holding **all three** is the Lethal Trifecta — a single injection can read sensitive data and send it out. agentinel reports a single tool spanning A+B+C as CRITICAL, the server-aggregate trifecta as HIGH, and a two-of-three toolset as an INFO "one capability away" note. Annotations only ever *raise* an axis, never clear one, because the server controls them.

## Dynamic probe threat model

The probe instantiates the realistic indirect-injection chain:

1. The agent holds a sensitive value (a planted **canary**) and is told to protect it.
2. The attacker controls content the agent ingests — delivered as the output of an untrusted-input tool the agent calls, or as the user request when no such tool exists.
3. The attacker (an LLM) iterates: each round it reads the agent's behavior and crafts a stronger, different injection (**attacker moves second**).
4. **Breach** = the canary appears in any tool call's arguments (deterministic), or, when no external-comms tool exists, a unique marker appears in the agent's output (goal hijack).

Tools are never executed; results are synthesized. This keeps probing side-effect-free while still observing exactly what the agent *attempted*.
