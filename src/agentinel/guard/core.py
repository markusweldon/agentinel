"""Session-aware Rule of Two: ask a human only when a call would complete the lethal trifecta.

A static scan answers "could this agent's tools combine into an exfiltration path?" — and for a
useful agent the answer is almost always yes. The guard asks a narrower question at runtime:
"has *this session* already pulled in untrusted input (A) and sensitive data (B), and is the agent
now about to take an external action (C)?" Only that call needs a human. Everything else runs.

This module is deliberately dependency-free (stdlib only) because it runs inside a hook on every
tool call, where import time is felt.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

A, B, C = "A", "B", "C"
LEG_NAMES = {A: "untrusted input", B: "sensitive data", C: "an external action"}
_MAX_SOURCES = 5
_MAX_FINGERPRINTS = 4000

# Tracking modes. "session": ask on any external action once the session holds A and B (simple,
# coarse). "flow": ask only when the external action's arguments carry a value this session read
# from a sensitive source (precise; misses data the agent paraphrases or re-encodes in new ways).
SESSION, FLOW = "session", "flow"


# --- value fingerprints ----------------------------------------------------------------------------
# Values read from a sensitive source are stored only as truncated SHA-256 hashes, never in plain
# text, so the state file is not itself a second copy of your secrets.
_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=.:@]{12,}")
_SECRET_KV = re.compile(
    r"(?i)\b[\w.-]*(token|secret|password|passwd|api[_-]?key|private[_-]?key|access[_-]?key|auth)[\w.-]*"
    r"[\"']?\s*[:=]\s*[\"']?([^\s\"',;]{6,})"
)
_MIN_LINE = 24
_SPLIT = re.compile(r"[=:@/?&]")


def _pieces(text: str) -> set[str]:
    """Tokens, plus the parts of each token between separators (so ``?t=<secret>`` yields the secret)."""
    out: set[str] = set()
    for tok in _TOKEN.findall(text):
        out.add(tok)
        out.update(p for p in _SPLIT.split(tok) if len(p) >= 12)
    return out


def _h(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:24]


def _entropy(s: str) -> float:
    counts = {ch: s.count(ch) for ch in set(s)}
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def _secretish(tok: str) -> bool:
    """A token that looks like a credential rather than a URL, path, version or branch name."""
    if "/" in tok or "://" in tok or tok.count(".") > 1:
        return False
    classes = sum(bool(re.search(p, tok)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[_\-+=]"))
    return len(tok) >= 20 and classes >= 3 and _entropy(tok) >= 3.6


def fingerprints_of(text: str, *, lines: bool = True) -> set[str]:
    """Hash the parts of a sensitive tool output worth recognising if they show up again.

    Credentials (``KEY=value`` pairs and high-entropy tokens) always. Whole lines only when
    ``lines`` is set: right for a sensitive file or document, wrong for a shell command's output,
    where most lines are ordinary (URLs, branch names) and would recur harmlessly.
    """
    fps: set[str] = set()
    if not text:
        return fps
    for m in _SECRET_KV.finditer(text):
        fps.add(_h(m.group(2).strip()))
    for tok in _pieces(text):
        if _secretish(tok):
            fps.add(_h(tok))
    if lines:
        for line in text.splitlines()[:500]:
            line = line.strip()
            if len(line) >= _MIN_LINE:
                fps.add(_h(line))
    return fps


def strings_in(value) -> list[str]:
    """Every string inside a JSON-like value (tool inputs and outputs are nested dicts/lists)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in strings_in(v)]
    if isinstance(value, list):
        return [s for v in value for s in strings_in(v)]
    return []


def _decodings(tok: str) -> list[str]:
    out = []
    if len(tok) >= 16 and re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", tok):
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                out.append(decoder(tok + "=" * (-len(tok) % 4)).decode("utf-8"))
                break
            except (binascii.Error, ValueError):
                continue
    if len(tok) >= 16 and len(tok) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", tok):
        try:
            out.append(bytes.fromhex(tok).decode("utf-8"))
        except ValueError:
            pass
    return out


def carries_fingerprint(args, fps: set[str]) -> bool:
    """True if any string in a tool call's arguments matches a fingerprinted value.

    Checks whole lines, individual tokens and key=value pieces, as written and after URL, base64
    and hex decoding. That catches verbatim and lightly encoded exfiltration; it can't catch a
    value the agent paraphrases, splits or encrypts.
    """
    if not fps:
        return False
    seen: set[str] = set()
    queue = list(strings_in(args))
    while queue:
        text = queue.pop()
        if text in seen or len(seen) > 20000:
            continue
        seen.add(text)
        decoded = unquote(text)
        if decoded != text:
            queue.append(decoded)
        candidates = {line.strip() for line in text.splitlines()}
        pieces = _pieces(text)
        candidates.update(pieces)
        candidates.update(m.group(2) for m in _SECRET_KV.finditer(text))
        for cand in candidates:
            if cand and _h(cand) in fps:
                return True
        for tok in pieces:
            queue.extend(_decodings(tok))
    return False


@dataclass
class Decision:
    ask: bool
    reason: str = ""


@dataclass
class SessionState:
    """Which taint legs (A, B) this session has touched, and which calls supplied them."""

    sources: dict[str, list[str]] = field(default_factory=dict)
    fingerprints: set[str] = field(default_factory=set)

    @property
    def legs(self) -> set[str]:
        return {leg for leg, srcs in self.sources.items() if srcs}

    def add(self, legs: set[str], source: str, output: str = "", *, lines: bool = True) -> None:
        # C is an action, not a taint: doing something external doesn't make later calls riskier.
        for leg in sorted(legs & {A, B}):
            srcs = self.sources.setdefault(leg, [])
            if source not in srcs and len(srcs) < _MAX_SOURCES:
                srcs.append(source)
        if B in legs and output and len(self.fingerprints) < _MAX_FINGERPRINTS:
            self.fingerprints.update(
                list(fingerprints_of(output, lines=lines))[: _MAX_FINGERPRINTS - len(self.fingerprints)]
            )

    def remember(self, value: str, source: str) -> None:
        """Mark one known secret (e.g. a credential in the agent's own context) as sensitive data."""
        self.add({B}, source)
        self.fingerprints.add(_h(value))

    def to_json(self) -> dict:
        return {"sources": self.sources, "fingerprints": sorted(self.fingerprints)}

    @classmethod
    def from_json(cls, data: dict) -> SessionState:
        raw = data.get("sources") if isinstance(data, dict) else None
        if not isinstance(raw, dict):
            return cls()
        fps = data.get("fingerprints")
        if not isinstance(fps, list):
            fps = []
        return cls(
            sources={k: [str(s) for s in v][:_MAX_SOURCES] for k, v in raw.items() if k in (A, B)},
            fingerprints={str(f) for f in fps},
        )


def decide(
    state: SessionState,
    call_legs: set[str],
    tool: str,
    args=None,
    *,
    mode: str = FLOW,
) -> Decision:
    """Decide whether this call needs a human.

    Always requires: the call is an external action (C) and the session holds untrusted input (A).
    ``session`` mode then asks if the session has touched sensitive data (B) at all. ``flow`` mode
    asks only if the call's arguments carry a value read from a sensitive source, or if the tool
    itself reads sensitive data as well as acting externally (its internals are invisible to us).
    """
    if C not in call_legs:
        return Decision(ask=False)
    if A not in state.legs | call_legs:
        return Decision(ask=False)

    def src(leg: str) -> str:
        names = list(state.sources.get(leg, []))
        if leg in call_legs and tool not in names:
            names.append(tool)
        return ", ".join(names) or tool

    if mode == SESSION:
        if B not in state.legs | call_legs:
            return Decision(ask=False)
        why = f"and sensitive data ({src(B)}). {tool} can send data out"
    elif B in call_legs:
        why = f"and {tool} can both read sensitive data and send data out"
    elif carries_fingerprint(args, state.fingerprints):
        why = f"and this call to {tool} carries data the session read from {src(B)}"
    else:
        return Decision(ask=False)

    reason = (
        f"Agentinel guard: this session has read untrusted input ({src(A)}) {why}, so a prompt "
        "injection in that input could be leaking it. Approve only if you expected this."
    )
    return Decision(ask=True, reason=reason)


def guard_home() -> Path:
    return Path(os.environ.get("AGENTINEL_GUARD_HOME") or Path.home() / ".agentinel" / "guard")


class SessionStore:
    """One small JSON file per session id, written atomically."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or guard_home()) / "sessions"

    def path(self, session_id: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", session_id or "")[:128].strip(".") or "default"
        return self.root / f"{safe}.json"

    def load(self, session_id: str) -> SessionState:
        try:
            return SessionState.from_json(json.loads(self.path(session_id).read_text()))
        except (OSError, ValueError):
            return SessionState()

    def save(self, session_id: str, state: SessionState) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = self.path(session_id)
        fd, tmp = tempfile.mkstemp(dir=self.root, prefix=".tmp-", suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump(state.to_json(), fh)
        os.replace(tmp, target)
