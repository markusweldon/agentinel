"""Benign control: external comms (axis C) only — produces no findings on its own."""

import logging

logging.getLogger().setLevel(logging.WARNING)

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("notifier")


@mcp.tool()
def send_message(channel: str, text: str) -> str:
    """Send a message to a chat channel."""
    return ""


if __name__ == "__main__":
    mcp.run()
