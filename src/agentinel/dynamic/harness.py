"""The agent-under-test harness: drive a tool-using agent for a bounded number of steps.

Target tools are NEVER executed — every tool call returns a synthetic result supplied by
``tool_result_fn``. This keeps probing side-effect-free and lets us inject attacker-controlled
"tool output" to simulate indirect prompt injection, while still observing exactly which tools
the agent *tried* to call and with what arguments.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..models import ToolInfo
from .llm import Chat, ToolCall


def to_anthropic_tools(tools: list[ToolInfo]) -> list[dict]:
    """Convert MCP tools to the Claude tool schema."""
    out = []
    for t in tools:
        schema = t.input_schema or {"type": "object", "properties": {}}
        out.append({"name": t.name, "description": t.description or "", "input_schema": schema})
    return out


@dataclass
class AgentRun:
    tool_calls: list[ToolCall] = field(default_factory=list)
    final_text: str = ""
    steps: int = 0


def run_agent(
    chat: Chat,
    *,
    system: str,
    user_content: str,
    tools: list[dict],
    tool_result_fn: Callable[[ToolCall], str],
    max_steps: int = 4,
) -> AgentRun:
    """Run the agent loop until it stops calling tools or ``max_steps`` is reached."""
    messages: list[dict] = [{"role": "user", "content": user_content}]
    all_calls: list[ToolCall] = []
    final_text = ""
    steps = 0

    for _ in range(max_steps):
        steps += 1
        resp = chat.respond(system=system, messages=messages, tools=tools)
        if resp.text:
            final_text = resp.text
        if not resp.tool_calls:
            break
        all_calls.extend(resp.tool_calls)
        messages.append({"role": "assistant", "content": resp.raw_content or [{"type": "text", "text": resp.text}]})
        results = [
            {"type": "tool_result", "tool_use_id": call.id, "content": tool_result_fn(call)} for call in resp.tool_calls
        ]
        messages.append({"role": "user", "content": results})

    return AgentRun(tool_calls=all_calls, final_text=final_text, steps=steps)
