"""Tests for config parsing and fleet (multi-server) scanning."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from agentinel.config import parse_config
from agentinel.scanner import scan_config
from agentinel.taxonomy import AttackClass, Severity

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_PY = sys.executable


def _write_fleet_config(tmp_path: Path, servers: dict[str, str]) -> Path:
    cfg = {"mcpServers": {name: {"command": _PY, "args": [str(_FIXTURES / rel)]} for name, rel in servers.items()}}
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(cfg))
    return path


def test_parse_config_handles_stdio_http_and_skips_invalid(tmp_path):
    cfg = {
        "mcpServers": {
            "a": {"command": "python", "args": ["server.py", "--flag"]},
            "b": {"url": "https://example.test/mcp"},
            "c": {"env": {"K": "v"}},  # no command or url -> skipped
        }
    }
    path = tmp_path / "c.json"
    path.write_text(json.dumps(cfg))
    specs = {s.name: s for s in parse_config(path)}

    assert specs["a"].transport == "stdio" and "server.py" in specs["a"].command
    assert specs["b"].transport == "http" and specs["b"].url.endswith("/mcp")
    assert "c" not in specs


async def test_fleet_detects_cross_server_trifecta(tmp_path):
    path = _write_fleet_config(
        tmp_path,
        {
            "fetcher": "clean/fetch_only_server.py",  # axis A
            "files": "clean/files_only_server.py",  # axis B
            "notifier": "clean/comms_only_server.py",  # axis C
        },
    )
    report = await scan_config(str(path))

    # The fleet combination is a trifecta even though no single server is.
    assert any(f.attack_class is AttackClass.LETHAL_TRIFECTA and f.target == "fleet" for f in report.findings)
    assert not any(
        f.attack_class is AttackClass.LETHAL_TRIFECTA
        and f.target.startswith("server:")
        and f.severity.rank >= Severity.HIGH.rank
        for f in report.findings
    )


async def test_config_secret_in_env_is_flagged(tmp_path):
    cfg = {
        "mcpServers": {
            "files": {
                "command": _PY,
                "args": [str(_FIXTURES / "clean/files_only_server.py")],
                "env": {"API_KEY": "sk-ABCDEFGHIJ1234567890"},
            }
        }
    }
    path = tmp_path / "c.json"
    path.write_text(json.dumps(cfg))
    report = await scan_config(str(path))

    assert any(f.attack_class is AttackClass.SECRETS_EXPOSURE for f in report.findings)
