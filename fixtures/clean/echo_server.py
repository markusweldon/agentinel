"""A benign MCP server used as a false-positive control in the eval corpus.

Read-only, no sensitive data, no external communication — should produce zero findings.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("echo-clean")


@mcp.tool()
def echo(text: str) -> str:
    """Echo back the provided text unchanged."""
    return text


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return their sum."""
    return a + b


@mcp.tool()
def word_count(text: str) -> int:
    """Count the number of whitespace-separated words in the given text."""
    return len(text.split())


if __name__ == "__main__":
    mcp.run()
