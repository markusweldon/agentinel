"""Connect to an MCP server as a client and capture a normalized snapshot.

Supports stdio and streamable-HTTP transports. The snapshot (tools + their descriptions,
schemas, and annotations, plus server-level instructions) is the raw material every static
detector works on, and the live session backs the dynamic probe.
"""

from __future__ import annotations

import asyncio
import inspect
import os
from contextlib import asynccontextmanager
from shlex import split as shlex_split

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client
from pydantic import BaseModel, Field

from .models import ToolInfo

DEFAULT_TIMEOUT = 30.0

# stdio_client gained an `errlog` parameter to redirect the child's stderr; detect it so we
# can silence noisy servers without breaking on older SDKs.
_STDIO_SUPPORTS_ERRLOG = "errlog" in inspect.signature(stdio_client).parameters


class ServerSnapshot(BaseModel):
    """Everything the static engine needs about one connected server."""

    server_name: str
    server_version: str | None = None
    instructions: str | None = None
    tools: list[ToolInfo] = Field(default_factory=list)
    resources: list[dict] = Field(default_factory=list)
    prompts: list[dict] = Field(default_factory=list)
    command: str | None = None
    env: dict[str, str] | None = None


@asynccontextmanager
async def _stdio_session(command: str, args: list[str], env: dict[str, str] | None, errlog):
    params = StdioServerParameters(command=command, args=args, env=env)
    if errlog is not None and _STDIO_SUPPORTS_ERRLOG:
        cm = stdio_client(params, errlog=errlog)
    else:
        cm = stdio_client(params)
    async with cm as (read, write):
        async with ClientSession(read, write) as session:
            yield session


@asynccontextmanager
async def _http_session(url: str, headers: dict[str, str] | None):
    async with streamablehttp_client(url, headers=headers) as (read, write, *_):
        async with ClientSession(read, write) as session:
            yield session


async def _enumerate(session: ClientSession, fallback_name: str) -> ServerSnapshot:
    """Initialize the session and pull tools, resources, and prompts."""
    init = await session.initialize()

    # MCP types use wire-style camelCase; read defensively across SDK versions.
    info = getattr(init, "serverInfo", None) or getattr(init, "server_info", None)
    server_name = (getattr(info, "name", None) if info else None) or fallback_name
    server_version = getattr(info, "version", None) if info else None
    instructions = getattr(init, "instructions", None)

    tools: list[ToolInfo] = []
    for t in (await session.list_tools()).tools:
        annotations = t.annotations.model_dump(exclude_none=True) if t.annotations else None
        tools.append(
            ToolInfo(
                server=server_name,
                name=t.name,
                description=t.description,
                input_schema=t.inputSchema or {},
                annotations=annotations,
            )
        )

    # Resources and prompts are optional capabilities; tolerate servers that lack them.
    resources: list[dict] = []
    prompts: list[dict] = []
    try:
        resources = [r.model_dump(exclude_none=True) for r in (await session.list_resources()).resources]
    except Exception:
        pass
    try:
        prompts = [p.model_dump(exclude_none=True) for p in (await session.list_prompts()).prompts]
    except Exception:
        pass

    return ServerSnapshot(
        server_name=server_name,
        server_version=server_version,
        instructions=instructions,
        tools=tools,
        resources=resources,
        prompts=prompts,
    )


async def connect_stdio(
    command: str,
    *,
    env: dict[str, str] | None = None,
    inherit_env: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    quiet: bool = False,
) -> ServerSnapshot:
    """Launch a stdio MCP server from a command string and enumerate it.

    By default the server runs with the SDK's minimal default environment. Pass
    ``inherit_env=True`` to forward the current process environment (some servers need it).
    Pass ``quiet=True`` to discard the child's stderr.
    """
    parts = shlex_split(command)
    if not parts:
        raise ValueError("empty stdio command")
    if inherit_env and env is None:
        env = dict(os.environ)

    devnull = open(os.devnull, "w") if quiet else None
    try:
        async with asyncio.timeout(timeout):
            async with _stdio_session(parts[0], parts[1:], env, devnull) as session:
                snap = await _enumerate(session, fallback_name=parts[0])
    finally:
        if devnull is not None:
            devnull.close()
    snap.command = command
    return snap


async def connect_http(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> ServerSnapshot:
    """Connect to a streamable-HTTP MCP server and enumerate it."""
    async with asyncio.timeout(timeout):
        async with _http_session(url, headers) as session:
            snap = await _enumerate(session, fallback_name=url)
    snap.command = url
    return snap
