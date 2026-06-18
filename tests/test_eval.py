"""Self-eval: run the scanner against the labeled fixture corpus and measure precision/recall.

This is agentinel eating its own dog food — the corpus is ground truth, and we assert the static
engine recovers every expected attack class with zero false positives on the clean controls.
Run with ``-s`` to see the printed metrics.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from agentinel.scanner import scan_stdio
from agentinel.taxonomy import AttackClass, Severity

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _cmd(rel: str) -> str:
    return f"{sys.executable} {_FIXTURES / rel}"


# path -> attack classes that MUST be detected
VULNERABLE: dict[str, set[AttackClass]] = {
    "vulnerable/poisoned_server.py": {
        AttackClass.TOOL_POISONING,
        AttackClass.LETHAL_TRIFECTA,
        AttackClass.UNSAFE_CODE_EXECUTION,
    },
    "vulnerable/trifecta_server.py": {AttackClass.LETHAL_TRIFECTA},
    "vulnerable/unicode_smuggle_server.py": {AttackClass.TOOL_POISONING},
}

# clean controls must yield no finding at or above LOW (an INFO near-trifecta note is allowed)
CLEAN = [
    "clean/echo_server.py",
    "clean/fetch_only_server.py",
    "clean/files_only_server.py",
]


@pytest.mark.parametrize("path,expected", VULNERABLE.items())
async def test_vulnerable_fixture_detected(path: str, expected: set[AttackClass]):
    report = await scan_stdio(_cmd(path), quiet=True)
    detected = {f.attack_class for f in report.findings}
    assert expected <= detected, f"{path}: missed {expected - detected}; detected {detected}"


@pytest.mark.parametrize("path", CLEAN)
async def test_clean_fixture_no_false_positives(path: str):
    report = await scan_stdio(_cmd(path), quiet=True)
    actionable = [f for f in report.findings if f.severity.rank >= Severity.LOW.rank]
    assert not actionable, f"{path}: false positives {[(f.attack_class.value, f.severity.value) for f in actionable]}"


async def test_corpus_precision_recall():
    expected_total = 0
    detected_total = 0
    for path, expected in VULNERABLE.items():
        report = await scan_stdio(_cmd(path), quiet=True)
        detected = {f.attack_class for f in report.findings}
        expected_total += len(expected)
        detected_total += len(expected & detected)

    false_positives = 0
    for path in CLEAN:
        report = await scan_stdio(_cmd(path), quiet=True)
        false_positives += sum(1 for f in report.findings if f.severity.rank >= Severity.LOW.rank)

    recall = detected_total / expected_total if expected_total else 1.0
    precision = detected_total / (detected_total + false_positives) if (detected_total + false_positives) else 1.0
    print(
        f"\n[self-eval] recall={recall:.2%}  precision={precision:.2%}  "
        f"(expected={expected_total} detected={detected_total} false_positives={false_positives})"
    )

    assert recall >= 0.9
    assert false_positives == 0
