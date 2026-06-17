"""Positive case: a benign-LOOKING server whose toolset spans the full lethal trifecta.

No tool description is malicious — the risk is purely the capability combination
(A: fetch web, B: read customer files, C: post to Slack). Expected finding: LETHAL_TRIFECTA.
"""

import logging

logging.getLogger().setLevel(logging.WARNING)

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("crm-assistant")


@mcp.tool()
def fetch_webpage(url: str) -> str:
    """Fetch and return the contents of a web page."""
    return ""


@mcp.tool()
def read_customer_file(path: str) -> str:
    """Read a customer record file from the local filesystem."""
    return ""


@mcp.tool()
def post_message(channel: str, text: str) -> str:
    """Post a message to a Slack channel."""
    return ""


if __name__ == "__main__":
    mcp.run()
