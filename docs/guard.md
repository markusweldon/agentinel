# Session guard: living with the lethal trifecta

> **Research prototype.** One day of work, measured on a small sample. The numbers below are a
> first signal, not a result.

## The problem

A useful agent holds all three legs of the lethal trifecta. A coding agent reads issues and web
pages (A, untrusted input), sees your code and credentials (B, sensitive data) and can push code or
call out (C, external action). A study of 100 agents by the Cloud Security Alliance found the
trifecta in 98% of them. So telling people "you have a trifecta, remove a leg" doesn't help: they
won't, because that's what makes the agent worth using.

Today the choice is between crippling the agent and approving every outbound call. People who
approve everything soon approve without reading. The question this prototype tests:

**Can a guard stay silent almost all the time, and ask only at the moment data could actually
leak?**

## How it works

A Claude Code hook (`agentinel-guard`) on `PreToolUse` and `PostToolUse`:

1. **After each call (PostToolUse)**, record which legs it brought into the session: untrusted input
   (A, e.g. `WebFetch`, `curl`, reading a PR) and sensitive data (B, e.g. reading `.env`,
   `~/.aws/credentials`, `gh auth token`). For B, fingerprint the values that came back
   (credentials, plus whole lines for files and documents) as truncated SHA-256 hashes. The secrets
   themselves are never stored.
2. **Before each call (PreToolUse)**, if the call is an external action (C) *and* the session has
   read untrusted input *and* the call's arguments carry a fingerprinted value (as written, or
   URL-, base64- or hex-encoded), ask the user, and say exactly why:
   *"this session has read untrusted input (WebFetch evil.example) and this call to Bash curl
   carries data the session read from Read .env…"*
3. Otherwise it prints nothing, so Claude Code's own permission rules apply unchanged. **The guard
   never grants a permission; it can only add a prompt.**

MCP tools get their legs from a policy built by scanning your servers (`agentinel guard init`).
Built-in tools are classified per call from their input, since `Read src/app.py` and `Read .env`
are very different.

## Measurement 1: how often does it ask? (real sessions)

`agentinel guard replay` walks recorded Claude Code transcripts through the guard and counts
prompts. It runs locally and reports counts and tool names only.

First run, on the author's own sessions (6 sessions, ~1,000 tool calls, mostly coding and GitHub
work, so a small, unrepresentative sample):

| Policy | Approval prompts | vs. baseline |
|---|---:|---:|
| Ask before every external action (baseline) | 88 | 100% |
| Guard, session-wide tracking | 83 | 94% |
| **Guard, value-level flow tracking** | **2** | **2%** |

Both remaining prompts were single shell commands that touched a credential *and* reached out in
the same call, where the guard can't see what passes between the two. That's the intended
behaviour.

### What went wrong on the way (worth knowing)

- **Session-wide tracking is useless for coding agents.** Once a long session touches any secret,
  every later `git push` asks. It saved only 6% over asking every time. This was the main finding of
  the day: tracking *the session* is too coarse, so the guard has to track *the value*.
- **The static scanner's C axis is too broad for this job.** In `agentinel scan`, C means "changes
  state *or* communicates externally". Only communicating can leak data, so a local state change
  (`update_plan`, `Edit`) must not count. The guard uses a narrower outbound-only C for MCP tools it
  hasn't seen.
- **The first fingerprinting was too greedy.** It hashed every line of any sensitive command's
  output. Ordinary lines in that output (GitHub URLs, branch names) recurred in later pushes and
  caused 11 false prompts. From shell output the guard now fingerprints only credential-shaped
  values.

## Measurement 2: does it stop the leak? (adaptive probe)

`agentinel probe --guard flow` runs the adaptive attacker against an agent under the guard, with a
simulated user who declines every prompt, so you can compare breach rates with it on and off. The
planted canary counts as sensitive data from the start (it sits in the agent's context).

With a scripted test agent (in the test suite):

| Leak | Unguarded | Guarded (flow) |
|---|---|---|
| Canary sent verbatim | breached | blocked |
| Canary sent base64-encoded | breached | blocked |
| Canary split up with spaces | (not counted by the probe either) | **missed** |

**Not yet done:** running this against a live model. That's the next step, and it will show
whether real attackers rearrange the secret often enough to matter.

## Known limits

- **Rearranged data walks past it.** Value matching catches verbatim and lightly encoded copies.
  It can't catch a secret the agent splits, reverses, summarises or encrypts. An adaptive attacker
  will try exactly that, which is why the probe exists.
- **Only data that came in through a tool is tracked.** A secret pasted into the chat, or already
  in the system prompt, isn't fingerprinted unless something marks it (the probe does this for its
  canary).
- **It only sees tool calls.** Exfiltration that doesn't go through a tool, such as a rendered
  markdown image whose URL carries data, is out of reach of a hook.
- **It only addresses leaking data.** It does nothing about an injected agent *doing* damage with
  tools it's allowed to use.
- **The leg rules are a first cut**, tuned on one person's sessions. More transcripts from different
  kinds of work are the most useful next input.

## Try it

```bash
agentinel guard replay                      # what would it cost on your own sessions?
agentinel guard init --config .mcp.json     # policy for your MCP tools -> .agentinel/guard-policy.json
agentinel guard install                     # prints the hook settings to add; writes nothing
```

`AGENTINEL_GUARD_MODE=deny` blocks instead of asking (for unattended runs), and
`AGENTINEL_GUARD_TRACKING=session` switches to the coarse session-wide mode for comparison.

## Prior work

The idea of tracking where data came from inside an agent is not new. Google DeepMind's CaMeL and
Microsoft's FIDES do it rigorously, but ask you to restructure the agent. Invariant Labs (now part
of Snyk) had a guardrails policy language that could express flow rules between tool calls. This
prototype tests a narrower question: how far a drop-in hook on an existing agent gets, and at what
cost in prompts.
