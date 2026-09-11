import asyncio
import os
import sys

from dotenv import load_dotenv

from google import genai

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


load_dotenv()


GEMINI_API_KEY = os.environ["GEMINI_API_KEY"]


async def analyze_ioc(ioc: str):

    client = genai.Client(api_key=GEMINI_API_KEY)

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["mcp_server.py"],
        env=os.environ.copy(),
    )

    async with stdio_client(server_params) as (read, write):

        async with ClientSession(read, write) as session:

            await session.initialize()

            # Let's verify that Gemini's MCP client can see the tools.
            tools = await session.list_tools()

            print("\nMCP tools available:")
            for tool in tools.tools:
                print(f"  - {tool.name}")

            # prompt = f"""
            # Use the identify_ioc_type MCP tool to determine the type of this IOC:
            #
            # {ioc}
            #
            # Do not call any other tools.
            #
            # After the tool returns, tell me the IOC type.
            # """

            # prompt = f"""
            # Use the identify_ioc_type MCP tool to determine the type of this IOC:
            #
            # {ioc}
            #
            # Do not call any other tools.
            #
            # After the tool returns, tell me the IOC type. If it an IP address, call the virustotal_lookup tool only.
            # """

            prompt = f"""
You are a senior cyber threat intelligence analyst.

Investigate this IOC:

{ioc}

Determine the IOC type first.

Then use the available threat intelligence tools to investigate it.

Use multiple sources when appropriate.

After gathering the available intelligence, provide:

1. Executive summary
2. Overall maliciousness assessment (High/Medium/Low)
3. Key findings from each source used
4. Malware families, if identified
5. MITRE ATT&CK techniques, if identified
6. Infrastructure observations
7. Confidence level
8. Recommended SOC actions
9. Recommended detection opportunities
10. Conflicting information between sources

Do not invent information that is not present in the tool results.
Clearly distinguish confirmed findings from inferences.
"""

            response = await client.aio.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config={
                    "temperature": 0,
                    "tools": [session],
                },
            )

            print("\n" + "=" * 80)
            print("GEMINI THREAT INTELLIGENCE ANALYSIS")
            print("=" * 80)
            print(response.text)
def main():
    ioc = os.environ['IOC']
    asyncio.run(analyze_ioc(ioc))

if __name__ == "__main__":
    #
    # ioc = input("IOC: ").strip()
    #
    # asyncio.run(analyze_ioc(ioc))
    main()