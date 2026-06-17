"""Parse MCP client config files into server specs.

Supports the common shapes: the ``mcpServers`` map used by Claude Code, Cursor, and Claude
Desktop, and the ``servers`` map used by VS Code. Each entry is either a stdio launcher
(``command`` + ``args`` + optional ``env``) or a remote (``url``).
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

COMMON_CONFIG_PATHS = [
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
]


class ServerSpec(BaseModel):
    name: str
    transport: Literal["stdio", "http"]
    command: str | None = None
    url: str | None = None
    env: dict[str, str] | None = None


def parse_config(path: str | Path) -> list[ServerSpec]:
    """Read a config file and return one ServerSpec per declared MCP server."""
    data = json.loads(Path(path).read_text())
    servers_map: dict = {}
    for key in ("mcpServers", "servers"):
        if isinstance(data.get(key), dict):
            servers_map = data[key]
            break

    specs: list[ServerSpec] = []
    for name, entry in servers_map.items():
        if not isinstance(entry, dict):
            continue
        env = entry.get("env") if isinstance(entry.get("env"), dict) else None
        url = entry.get("url")
        if url:
            specs.append(ServerSpec(name=name, transport="http", url=str(url), env=env))
            continue
        command = entry.get("command")
        if not command:
            continue
        args = entry.get("args") or []
        full = " ".join([str(command), *[shlex.quote(str(a)) for a in args]])
        specs.append(ServerSpec(name=name, transport="stdio", command=full, env=env))
    return specs


def discover_configs(root: str | Path = ".") -> list[Path]:
    """Return the common config files that exist under ``root``."""
    root = Path(root)
    return [root / rel for rel in COMMON_CONFIG_PATHS if (root / rel).is_file()]
