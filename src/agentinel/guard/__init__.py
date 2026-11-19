"""Session-aware Rule of Two guard: ask only when a call would complete the lethal trifecta."""

from .core import A, B, C, Decision, SessionState, SessionStore, decide

__all__ = ["A", "B", "C", "Decision", "SessionState", "SessionStore", "decide"]
