"""Benign control: pulls external content (axis A) only — should produce zero findings."""

import logging

logging.getLogger().setLevel(logging.WARNING)

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("docs-fetcher")


@mcp.tool()
def fetch_doc(url: str) -> str:
    """Fetch a public documentation page by URL and return its text."""
    return ""


@mcp.tool()
def search_docs(query: str) -> str:
    """Look up a topic in the public documentation index."""
    return ""


if __name__ == "__main__":
    mcp.run()
