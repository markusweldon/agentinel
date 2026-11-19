"""Replay recorded Claude Code sessions through the guard to measure what it would cost.

The research question is whether session-aware gating asks rarely enough to be worth having.
This reads ``~/.claude/projects/**/*.jsonl`` transcripts (or files you pass), walks every tool call
in order, and counts how often the guard would have asked, compared with a baseline that asks
before every external action. Nothing leaves the machine and only counts and tool names are
reported, never paths, commands or content.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .claude_code import legs_for, source_label
from .core import FLOW, SESSION, A, B, C, SessionState, decide, strings_in


@dataclass
class ReplayStats:
    sessions: int = 0
    tool_calls: int = 0
    external_calls: int = 0  # baseline: "approve every external action"
    session_prompts: int = 0  # guard, session-wide tracking
    prompts: int = 0  # guard, value-level flow tracking (the default)
    sessions_with_a: int = 0
    sessions_with_b: int = 0
    sessions_with_ab: int = 0
    sessions_prompted: int = 0
    prompt_tools: Counter = field(default_factory=Counter)
    a_tools: Counter = field(default_factory=Counter)
    b_tools: Counter = field(default_factory=Counter)

    def to_json(self) -> dict:
        return {
            "sessions": self.sessions,
            "tool_calls": self.tool_calls,
            "external_calls": self.external_calls,
            "session_mode_prompts": self.session_prompts,
            "flow_mode_prompts": self.prompts,
            "sessions_with_untrusted_input": self.sessions_with_a,
            "sessions_with_sensitive_data": self.sessions_with_b,
            "sessions_with_both": self.sessions_with_ab,
            "sessions_prompted": self.sessions_prompted,
            "prompt_tools": dict(self.prompt_tools.most_common()),
            "untrusted_input_tools": dict(self.a_tools.most_common()),
            "sensitive_data_tools": dict(self.b_tools.most_common()),
        }


def default_transcripts() -> list[Path]:
    root = Path.home() / ".claude" / "projects"
    return sorted(root.glob("**/*.jsonl")) if root.is_dir() else []


def iter_tool_calls(path: Path) -> Iterator[tuple[str, dict, str]]:
    """Yield (tool_name, tool_input, tool_output) for every tool call, in transcript order."""
    pending: dict[str, tuple[str, dict]] = {}
    order: list[str] = []
    outputs: dict[str, str] = {}
    with path.open(errors="replace") as fh:
        for line in fh:
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if not isinstance(obj, dict):
                continue
            content = (obj.get("message") or {}).get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if not isinstance(block, dict):
                    continue
                if obj.get("type") == "assistant" and block.get("type") == "tool_use" and block.get("name"):
                    tid = str(block.get("id") or len(order))
                    tin = block.get("input")
                    pending[tid] = (str(block["name"]), tin if isinstance(tin, dict) else {})
                    order.append(tid)
                elif obj.get("type") == "user" and block.get("type") == "tool_result":
                    outputs[str(block.get("tool_use_id"))] = "\n".join(strings_in(block.get("content")))
    for tid in order:
        name, tin = pending[tid]
        yield name, tin, outputs.get(tid, "")


def _tool_kind(name: str) -> str:
    """Report MCP tools by server only, so tool names from private servers stay coarse."""
    if name.startswith("mcp__"):
        parts = name.split("__")
        return f"mcp:{parts[1]}" if len(parts) > 1 else "mcp"
    return name


def replay(paths: Iterable[Path], policy: dict[str, set[str]] | None = None) -> ReplayStats:
    stats = ReplayStats()
    for path in paths:
        calls = list(iter_tool_calls(path))
        if not calls:
            continue
        stats.sessions += 1
        state = SessionState()
        prompted = False
        for name, tin, output in calls:
            stats.tool_calls += 1
            legs = legs_for(name, tin, policy)
            if C in legs:
                stats.external_calls += 1
            if decide(state, legs, name, tin, mode=SESSION).ask:
                stats.session_prompts += 1
            if decide(state, legs, name, tin, mode=FLOW).ask:
                stats.prompts += 1
                stats.prompt_tools[_tool_kind(name)] += 1
                prompted = True
            if A in legs:
                stats.a_tools[_tool_kind(name)] += 1
            if B in legs:
                stats.b_tools[_tool_kind(name)] += 1
            # The transcript shows the call was made; record what it brought into the session.
            state.add(legs, source_label(name, tin), output, lines=name != "Bash")
        stats.sessions_with_a += A in state.legs
        stats.sessions_with_b += B in state.legs
        stats.sessions_with_ab += {A, B} <= state.legs
        stats.sessions_prompted += prompted
    return stats
