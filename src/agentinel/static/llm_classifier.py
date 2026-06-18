"""Optional LLM-assisted capability classifier.

The keyword heuristic in classifier.py is fast and offline but brittle on unusually phrased
tools. This asks a model to read each tool's semantics and assign the three lethal-trifecta axes,
falling back to the heuristic on any error (including no API key). Wire it in with
``agentinel scan --llm-classify``.
"""

from __future__ import annotations

import json

from ..models import CapabilityAxes, ToolInfo
from .classifier import classify_tool

_SYSTEM = "You are a precise security classifier for MCP tools. Output JSON only, no prose."


def _extract_json(text: str) -> str:
    i, j = text.find("{"), text.rfind("}")
    return text[i : j + 1] if 0 <= i < j else text


def classify_tool_llm(tool: ToolInfo, chat) -> CapabilityAxes:
    """Classify a tool via the model; fall back to the heuristic on any failure."""
    params = list((tool.input_schema or {}).get("properties", {}).keys())
    prompt = (
        "Classify this MCP tool into the three lethal-trifecta axes. Respond ONLY with JSON:\n"
        '{"a": <bool>, "b": <bool>, "c": <bool>, "why": {"a": "...", "b": "...", "c": "..."}}\n'
        "A = ingests untrusted or external content; B = touches sensitive data or systems; "
        "C = changes state or communicates externally.\n\n"
        f"name: {tool.name}\ndescription: {tool.description or ''}\nparameters: {params}"
    )
    try:
        resp = chat.respond(system=_SYSTEM, messages=[{"role": "user", "content": prompt}])
        data = json.loads(_extract_json(resp.text))
        why = data.get("why") or {}
        rationale = {k.upper(): str(v) for k, v in why.items() if v}
        return CapabilityAxes(
            untrusted_input=bool(data.get("a")),
            sensitive_access=bool(data.get("b")),
            external_comms=bool(data.get("c")),
            rationale=rationale or {"source": "llm"},
        )
    except Exception:
        return classify_tool(tool)


def llm_classifier(model: str = "claude-sonnet-4-6"):
    """Return a ``classifier(tool) -> CapabilityAxes`` backed by an LLM (heuristic fallback)."""
    from ..dynamic.llm import AnthropicChat

    chat = AnthropicChat(model)
    return lambda tool: classify_tool_llm(tool, chat)
