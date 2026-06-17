# Responsible use

trident is a defensive security tool. The static `scan` is read-only and safe to run against any server. The dynamic `probe` generates adversarial input to manipulate a live agent — treat it like any other red-team tool.

## Rules

1. **Only probe what you own or are authorized to test.** Running `trident probe` against a third party's MCP server without explicit permission may be unlawful and is not a supported use case. The static `scan` is fine for any server you can connect to.
2. **No real secrets.** The probe plants a synthetic canary; never substitute production credentials.
3. **No side effects.** trident does not execute the target server's tools — it observes intended tool calls and synthesizes results. Do not modify it to actually invoke tools against systems you don't control.
4. **Responsible disclosure.** If you find a vulnerability in someone else's MCP server, report it privately to the maintainer and allow reasonable time to fix before any public discussion.

## Research and aggregate reporting

Any public write-up that scans a population of servers (e.g. "we audited N popular MCP servers") must:

- report findings **in aggregate** (rates and classes), not as a name-and-shame list;
- complete responsible disclosure for any specific, exploitable issue before publishing details;
- never publish a working exploit against a server you do not control.

trident exists to make the agent ecosystem safer. Use it that way.
