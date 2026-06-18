"""LLM classifier parses model JSON and falls back to the heuristic on bad output (no key needed)."""

from __future__ import annotations

from agentinel.dynamic.llm import ChatResponse, ScriptedChat
from agentinel.models import ToolInfo
from agentinel.static.llm_classifier import classify_tool_llm


def test_parses_model_classification():
    chat = ScriptedChat(
        lambda s, m, t, i: ChatResponse(
            text='{"a": true, "b": false, "c": true, "why": {"a": "reads web", "c": "posts"}}'
        )
    )
    axes = classify_tool_llm(ToolInfo(server="s", name="x", description="does things"), chat)
    assert axes.untrusted_input and axes.external_comms and not axes.sensitive_access


def test_falls_back_to_heuristic_on_bad_json():
    chat = ScriptedChat(lambda s, m, t, i: ChatResponse(text="sorry, I can't do that"))
    axes = classify_tool_llm(ToolInfo(server="s", name="fetch_url", description="Fetch a web page."), chat)
    # heuristic fallback recognizes a fetch tool as untrusted-input (A)
    assert axes.untrusted_input
