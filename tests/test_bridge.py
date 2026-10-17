"""Protocol smoke test; run with python -m unittest discover -s tests."""

import asyncio
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import threading
import unittest
from urllib.parse import parse_qs, urlparse

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class GhidraHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/status":
            body = json.dumps({"mode": "Headless", "programName": "fixture.exe"})
        elif url.path == "/methods":
            if url.query:
                assert parse_qs(url.query) == {"offset": ["1"], "limit": ["2"]}
            body = "main\nhelper"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        assert self.path == "/decompile" and body == b"main"
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"int main(void) { return 0; }")

    def log_message(self, *args):
        pass


class BridgeTest(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_round_trip(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), GhidraHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            await asyncio.wait_for(self.check_bridge(server.server_port), timeout=30)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    async def check_bridge(self, port):
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(Path(__file__).resolve().parents[1] / "bridge_mcp_ghidra.py"),
                  "--enable-headless-tools", "--default-ghidra-server",
                  f"http://127.0.0.1:{port}/"],
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = {tool.name: tool for tool in (await session.list_tools()).tools}
                self.assertIn("open_artifact_headless", tools)
                self.assertIn("name", tools["decompile_function"].inputSchema["required"])
                for name, arguments, expected in [
                    ("get_ghidra_status", {}, "Program: fixture.exe"),
                    ("list_methods", {"offset": 1, "limit": 2}, "helper"),
                    ("decompile_function", {"name": "main"}, "return 0;"),
                ]:
                    result = await session.call_tool(name, arguments)
                    self.assertFalse(result.isError, result)
                    self.assertIn(expected, "\n".join(item.text for item in result.content))


if __name__ == "__main__":
    unittest.main()
