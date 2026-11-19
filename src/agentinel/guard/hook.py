"""Claude Code hook entry point: ``agentinel-guard`` (or ``python -m agentinel.guard``).

Register it for both ``PreToolUse`` and ``PostToolUse``:

- **PostToolUse** records which legs (A untrusted input, B sensitive data) a call that actually ran
  brought into the session.
- **PreToolUse** asks for approval only when the call is an external action (C), the session has
  read untrusted input (A), and the call's arguments carry data read from a sensitive source (B).
  Otherwise it prints nothing, so Claude Code's normal permission rules
  apply unchanged: the guard never grants a permission, it can only add a prompt.

Set ``AGENTINEL_GUARD_MODE=deny`` to block instead of ask (for unattended runs), and
``AGENTINEL_GUARD_TRACKING=session`` for the coarser session-wide tracking instead of the
default value-level ``flow`` tracking. Errors fail open
with a note on stderr, so a bug in the guard can't wedge a session.
"""

from __future__ import annotations

import json
import os
import sys

from .claude_code import legs_for, load_policy, source_label
from .core import FLOW, SESSION, SessionStore, decide, strings_in


def handle(event: dict, store: SessionStore | None = None) -> dict | None:
    """Process one hook event; return the JSON to print, or None for "no opinion"."""
    store = store or SessionStore()
    kind = event.get("hook_event_name")
    tool = str(event.get("tool_name") or "")
    tin = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    sid = str(event.get("session_id") or "default")
    if not tool or kind not in ("PreToolUse", "PostToolUse"):
        return None

    legs = legs_for(tool, tin, load_policy(event.get("cwd")))
    state = store.load(sid)

    if kind == "PostToolUse":
        if legs:
            output = "\n".join(strings_in(event.get("tool_response")))
            state.add(legs, source_label(tool, tin), output, lines=tool != "Bash")
            store.save(sid, state)
        return None

    mode = SESSION if os.environ.get("AGENTINEL_GUARD_TRACKING", "").lower() == SESSION else FLOW
    decision = decide(state, legs, source_label(tool, tin), tin, mode=mode)
    if not decision.ask:
        return None
    verdict = "deny" if os.environ.get("AGENTINEL_GUARD_MODE", "").lower() == "deny" else "ask"
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": verdict,
            "permissionDecisionReason": decision.reason,
        }
    }


def main() -> int:
    try:
        event = json.load(sys.stdin)
        out = handle(event) if isinstance(event, dict) else None
    except Exception as exc:  # noqa: BLE001 - fail open; never break the user's session
        print(f"agentinel guard: skipped ({exc.__class__.__name__}: {exc})", file=sys.stderr)
        return 0
    if out is not None:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
