"""Drive an installed MCP server the way a host does: initialize, list tools, call one."""

import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main(command: str) -> None:
    parameters = StdioServerParameters(command=command, args=[], env={"PATH": ""})
    async with stdio_client(parameters) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = {tool.name for tool in (await session.list_tools()).tools}
        result = await session.call_tool(
            "defender_to_utc", {"timestamp": "2026-09-10T14:00:00", "assume_zone": "Europe/Rome"}
        )
    assert "defender_get_incident_evidence" in tools, tools
    assert "defender_isolate_machine" not in tools, "response actions must be off by default"
    assert json.loads(result.content[0].text) == {"utc": "2026-09-10T12:00:00Z"}, result
    print(f"standalone: {len(tools)} tools, call ok")


asyncio.run(main(sys.argv[1]))
