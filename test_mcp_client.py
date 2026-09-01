"""Minimal MCP client — proves server.py works over the real MCP stdio protocol.

This is exactly what an MCP host (Claude Desktop, Claude Code) does under the hood:
launch the server as a subprocess, speak MCP over stdin/stdout, discover its tools,
and call one. If this prints a triage result, the server is wired correctly.

    python test_mcp_client.py

Needs ANTHROPIC_API_KEY (server.py reads it from .env automatically).
"""

from __future__ import annotations

import asyncio
import json

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = StdioServerParameters(
    command="python",
    args=["C:\\dev\\Claude\\cerberus-ai\\server.py"],
)

SAMPLE_LOG = (
    "Aug 21 08:15:02 target-host sshd[9931]: Failed password for root "
    "from 203.0.113.66 port 40912 ssh2"
)


async def main() -> None:
    async with stdio_client(SERVER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("Tools exposed by the server:")
            for t in tools.tools:
                print(f"  - {t.name}: {t.description.splitlines()[0]}")

            print(f"\nCalling analyze_security_log on:\n  {SAMPLE_LOG}\n")
            result = await session.call_tool(
                "analyze_security_log", {"raw_log": SAMPLE_LOG}
            )

            # The tool returns a dict; the SDK wraps it as structured content.
            payload = result.structured_content or {}
            if not payload and result.content:
                # Fall back to the text block if structured content isn't present.
                payload = json.loads(result.content[0].text)

            print("=== Triage result (over MCP) ===")
            print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
