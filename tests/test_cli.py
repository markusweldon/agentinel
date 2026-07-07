"""CLI exit-code contract — what CI gating and the GitHub Action depend on.

  exit 2 = bad usage / connection failure   exit 1 = findings met --fail-on   exit 0 = pass
"""

from __future__ import annotations

import sys
from pathlib import Path

from typer.testing import CliRunner

from agentinel.cli import app

runner = CliRunner()
_FIX = Path(__file__).resolve().parent.parent / "fixtures"


def test_requires_exactly_one_target():
    assert runner.invoke(app, ["scan"]).exit_code == 2  # none
    assert runner.invoke(app, ["scan", "--stdio", "x", "--http", "y"]).exit_code == 2  # two


def test_llm_classify_without_key_exits_2(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert runner.invoke(app, ["scan", "--stdio", "x", "--llm-classify"]).exit_code == 2


def test_clean_server_exits_zero():
    cmd = f"{sys.executable} {_FIX / 'clean' / 'echo_server.py'}"
    assert runner.invoke(app, ["scan", "--stdio", cmd]).exit_code == 0


def test_poisoned_server_fails_the_gate():
    cmd = f"{sys.executable} {_FIX / 'vulnerable' / 'poisoned_server.py'}"
    assert runner.invoke(app, ["scan", "--stdio", cmd, "--fail-on", "high"]).exit_code == 1


def test_version_prints_and_exits_zero():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0 and result.output.strip()
