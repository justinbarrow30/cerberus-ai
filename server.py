"""CerberusAI MCP server — transport layer only.

Exposes the triage engine as an MCP tool over stdio so any MCP client
(Claude Desktop, Claude Code, a custom client) can call it. All real logic lives
in engine.py; this file just adapts it to the Model Context Protocol.

Run directly:   python server.py
Register it in an MCP client via the command `python /abs/path/to/server.py`.
"""

from __future__ import annotations

# In the `mcp` 2.x SDK the high-level server class is `MCPServer` (it was named
# `FastMCP` in 1.x). Same ergonomics: a `.tool()` decorator and `.run()` (stdio
# by default). If you install the standalone `fastmcp` package instead, swap this
# import for `from fastmcp import FastMCP` — the decorator API is compatible.
from mcp.server import MCPServer

from engine import MODEL, triage
from engine import _log as log

mcp = MCPServer("cerberus-ai")


@mcp.tool()
async def analyze_security_log(raw_log: str) -> dict:
    """Triage a single raw SIEM/syslog event and return structured threat intelligence.

    Returns a JSON object with: is_active_exploit, threat_score (0-10), category,
    summary, indicators, recommended_triage_actions, confidence.

    Args:
        raw_log: One raw log event exactly as it appears in Splunk/Elastic/Wazuh/syslog.
    """
    result = await triage(raw_log)
    # MCP tools return JSON-serializable data; hand back a plain dict.
    return result.model_dump()


if __name__ == "__main__":
    log(f"starting CerberusAI MCP server (model={MODEL}, transport=stdio)")
    mcp.run()  # defaults to stdio transport
