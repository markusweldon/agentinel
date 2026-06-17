"""Benign control: reads local files (axis B) only — should produce zero findings."""

import logging

logging.getLogger().setLevel(logging.WARNING)

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("notes-reader")


@mcp.tool()
def read_file(name: str) -> str:
    """Read a file from the local notes directory."""
    return ""


@mcp.tool()
def list_files() -> str:
    """List the files in the local notes directory."""
    return ""


if __name__ == "__main__":
    mcp.run()
