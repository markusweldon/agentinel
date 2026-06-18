"""Heuristic Rule-of-Two capability classification for MCP tools.

Classifies each tool into the three lethal-trifecta axes:

  A (untrusted_input)  — ingests untrusted / external content
  B (sensitive_access) — touches sensitive data or systems
  C (external_comms)   — can change state or communicate externally

Signals combine MCP tool annotations (``openWorldHint``, ``destructiveHint``, ``readOnlyHint``)
with curated keyword matches over the tool name, description, and parameter names/descriptions.

Design notes:
- Conservative term lists keep false positives low on benign tools.
- Annotations may only *raise* risk, never lower it — a server's self-declared ``readOnlyHint``
  is attacker-controllable, so we never use it to clear a keyword-derived capability.
"""

from __future__ import annotations

import re

from ..mcp_client import ServerSnapshot
from ..models import CapabilityAxes, ToolInfo

# A — pulls in external / untrusted content the model will then read.
_A_TERMS = [
    "fetch",
    "download",
    "scrape",
    "crawl",
    "browse",
    "web",
    "website",
    "webpage",
    "webhook",
    "rss",
    "feed",
    "read email",
    "read inbox",
    "inbox",
    "read message",
    "read messages",
    "read comment",
    "read comments",
    "read issue",
    "read issues",
    "incoming",
    "external content",
    "open url",
    "load page",
    "web search",
    "search web",
    "untrusted",
    "third party",
    "issue",
    "issues",
    "pull request",
    "pull requests",
    "discussion",
    "discussions",
    "comment",
    "comments",
    "gist",
    "notification",
    "notifications",
    "review",
    "reviews",
    "thread",
    "history",
]

# B — reaches sensitive data or systems.
_B_TERMS = [
    "secret",
    "secrets",
    "token",
    "credential",
    "credentials",
    "password",
    "api key",
    "private key",
    "access key",
    "ssh",
    "id rsa",
    "dotenv",
    "database",
    "sql",
    "read file",
    "get file",
    "file system",
    "filesystem",
    "list directory",
    "directory listing",
    "home directory",
    "aws",
    "s3",
    "gcp",
    "azure",
    "kubernetes",
    "kube",
    "private repo",
    "contacts",
    "calendar",
    "customer",
    "personal data",
    "pii",
    "payment",
    "billing",
    "credit card",
    "bank",
    "invoice",
    "salary",
    "etc passwd",
    "config file",
    "file",
    "files",
    "file contents",
    "media file",
]

# C — changes state or communicates outward.
_C_TERMS = [
    "send",
    "post",
    "publish",
    "tweet",
    "sms",
    "notify",
    "upload",
    "write",
    "create",
    "update",
    "delete",
    "remove",
    "push",
    "commit",
    "merge",
    "deploy",
    "transfer",
    "pay",
    "charge",
    "execute",
    "exec",
    "shell",
    "run command",
    "make request",
    "http post",
    "send email",
    "send message",
    "write file",
    "put",
    "patch",
]


def _normalize(text: str) -> str:
    """Lower-case, split camelCase, and turn separators into spaces for robust matching."""
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    text = re.sub(r"[_\-./]+", " ", text)
    return re.sub(r"\s+", " ", text).strip().lower()


def _matches(haystack: str, terms: list[str]) -> list[str]:
    """Return the terms that appear in ``haystack`` on token boundaries (avoids 'curl'~'url')."""
    hits: list[str] = []
    for term in terms:
        if re.search(rf"(?<![a-z]){re.escape(term)}(?![a-z])", haystack):
            hits.append(term)
    return hits


def _haystack(tool: ToolInfo) -> str:
    parts = [tool.name or "", tool.description or ""]
    props = (tool.input_schema or {}).get("properties", {})
    if isinstance(props, dict):
        for pname, pinfo in props.items():
            parts.append(str(pname))
            if isinstance(pinfo, dict) and pinfo.get("description"):
                parts.append(str(pinfo["description"]))
    return _normalize(" ".join(parts))


def _reason(hits: list[str], annotation: str | None = None) -> str:
    bits = []
    if hits:
        bits.append("matched: " + ", ".join(hits))
    if annotation:
        bits.append(f"annotation {annotation}")
    return "; ".join(bits)


def classify_tool(tool: ToolInfo) -> CapabilityAxes:
    """Classify a single tool into the three Rule-of-Two axes."""
    hay = _haystack(tool)
    ann = tool.annotations or {}

    a_hits = _matches(hay, _A_TERMS)
    b_hits = _matches(hay, _B_TERMS)
    c_hits = _matches(hay, _C_TERMS)

    open_world = ann.get("openWorldHint") is True
    destructive = ann.get("destructiveHint") is True
    not_read_only = ann.get("readOnlyHint") is False

    a = bool(a_hits) or open_world
    b = bool(b_hits)
    c = bool(c_hits) or destructive or not_read_only

    rationale: dict[str, str] = {}
    if a:
        rationale["A"] = _reason(a_hits, "openWorldHint=true" if open_world else None)
    if b:
        rationale["B"] = _reason(b_hits)
    if c:
        ann_note = "destructiveHint=true" if destructive else ("readOnlyHint=false" if not_read_only else None)
        rationale["C"] = _reason(c_hits, ann_note)

    return CapabilityAxes(untrusted_input=a, sensitive_access=b, external_comms=c, rationale=rationale)


def classify_snapshot(
    snapshot: ServerSnapshot,
    classifier=classify_tool,
) -> ServerSnapshot:
    """Populate ``tool.axes`` for every tool in the snapshot (in place) and return it."""
    for tool in snapshot.tools:
        tool.axes = classifier(tool)
    return snapshot
