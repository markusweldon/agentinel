"""A thin chat abstraction so the probe loop is provider-agnostic and unit-testable.

``AnthropicChat`` wraps the real Claude messages API; ``ScriptedChat`` lets tests drive the
loop deterministically with no API key.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict


@dataclass
class ChatResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw_content: list = field(default_factory=list)  # provider-native blocks, for continuation
    stop_reason: str | None = None


class Chat(Protocol):
    def respond(self, *, system: str, messages: list[dict], tools: list[dict] | None = None) -> ChatResponse: ...


class AnthropicChat:
    """Live Claude chat. Requires ANTHROPIC_API_KEY in the environment."""

    def __init__(self, model: str, *, max_tokens: int = 1024, client=None) -> None:
        self.model = model
        self.max_tokens = max_tokens
        if client is None:
            import anthropic  # lazy import — static scanning never needs it

            client = anthropic.Anthropic()
        self._client = client

    def respond(self, *, system, messages, tools=None) -> ChatResponse:
        kwargs = {"model": self.model, "max_tokens": self.max_tokens, "system": system, "messages": messages}
        if tools:
            kwargs["tools"] = tools
        msg = self._client.messages.create(**kwargs)
        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for block in msg.content:
            if getattr(block, "type", None) == "text":
                text_parts.append(block.text)
            elif getattr(block, "type", None) == "tool_use":
                calls.append(ToolCall(id=block.id, name=block.name, args=dict(block.input)))
        return ChatResponse(
            text="\n".join(text_parts),
            tool_calls=calls,
            raw_content=msg.content,
            stop_reason=msg.stop_reason,
        )


class ScriptedChat:
    """Test double. ``responder(system, messages, tools, call_index) -> ChatResponse``."""

    def __init__(self, responder: Callable[..., ChatResponse]) -> None:
        self._responder = responder
        self.calls: list[tuple] = []

    def respond(self, *, system, messages, tools=None) -> ChatResponse:
        idx = len(self.calls)
        self.calls.append((system, messages, tools))
        return self._responder(system, messages, tools, idx)
