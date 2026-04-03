[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)


# ghidraMCP
ghidraMCP is an Model Context Protocol server for allowing LLMs to autonomously reverse engineer applications. It exposes numerous tools from core Ghidra functionality to MCP clients.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9


# Quick Start

## GUI Mode (Plugin)
1. Build or download the extension: `GhidraMCP-1.0-SNAPSHOT.zip`
2. Install in Ghidra: `File` → `Install Extensions` → `+` → Select ZIP
3. Load a program - HTTP server starts automatically on a random port shown in the **GhidraMCP Status** window
4. Access endpoints: `curl http://127.0.0.1:<port>/methods` (use the port shown in the Status window)

## Headless Mode (Command Line)
```bash
# Optional: Set custom port
export GHIDRA_MCP_PORT=9090

# Run with analyzeHeadless
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
  /tmp/proj project_name \
  -import /path/to/binary \
  -postScript HeadlessMCPServerScript.java
```

## Automated Headless Mode (New!)
The new `open_artifact_headless` tool allows you to automatically start Ghidra headless analysis without manually running `analyzeHeadless`. This is especially useful for MCP clients.

### Prerequisites
- Set the `GHIDRA_INSTALL_DIR` environment variable to point to your Ghidra installation directory

### Usage
```bash
# Start the MCP bridge with headless tools enabled
python bridge_mcp_ghidra.py --enable-headless-tools

# Then use the headless tools through your MCP client
# open_artifact_headless will automatically:
# 1. Kill any existing Ghidra processes
# 2. Start analyzeHeadless in the background on a random available port
# 3. Wait for the server to become available
```

# Features
MCP Server + Ghidra Plugin

- Decompile and analyze binaries in Ghidra
- Automatically rename methods and data
- List methods, classes, imports, and exports

# Installation

## Prerequisites
- Install [Ghidra](https://ghidra-sre.org)
- Python3
- MCP [SDK](https://github.com/modelcontextprotocol/python-sdk)

## Ghidra
First, download the latest [release](https://github.com/LaurieWired/GhidraMCP/releases) from this repository. This contains the Ghidra plugin and Python MCP client. Then, you can directly import the plugin into Ghidra.

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhidraMCP-1-2.zip` (or your chosen version) from the downloaded release
5. Restart Ghidra
6. The **GhidraMCP Status** tab opens automatically in the bottom panel alongside Console and Bookmarks, and displays the server URL

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## MCP Clients

Theoretically, any MCP client should work with ghidraMCP.  Three examples are given below.

### Connecting to Ghidra

Because the plugin binds a random port on each startup, the bridge does not need a server URL at launch. There are two ways to point the bridge at Ghidra after it starts:

- **`open_artifact_headless`** — ask the LLM to load a binary. The bridge starts a Ghidra headless process automatically and connects to it. No port management needed.
- **`set_ghidra_server`** — if Ghidra is already running (GUI or headless), tell the LLM the URL shown in the **GhidraMCP Status** window and ask it to call `set_ghidra_server`:
  ```
  set_ghidra_server("http://127.0.0.1:<port>/")
  ```

## Example 1: Claude Desktop
To set up Claude Desktop as a Ghidra MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py"
      ]
    }
  }
}
```

Alternatively, edit this file directly:
```
/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json
```

Once connected, use `open_artifact_headless` to load a binary, or `set_ghidra_server` to point the bridge at a running Ghidra GUI instance.

## Example 2: Cline
To use GhidraMCP with [Cline](https://cline.bot), this requires manually running the MCP server as well. First run the following command:

```
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081
```

Once the MCP server is running, open up Cline and select `MCP Servers` at the top.

![Cline select](https://github.com/user-attachments/assets/88e1f336-4729-46ee-9b81-53271e9c0ce0)

Then select `Remote Servers` and add the following, ensuring that the url matches the MCP host and port:

1. Server Name: GhidraMCP
2. Server URL: `http://127.0.0.1:8081/sse`

Then use `open_artifact_headless` or `set_ghidra_server` to connect to a Ghidra instance.

## Example 3: 5ire
Another MCP client that supports multiple models on the backend is [5ire](https://github.com/nanbingxyz/5ire). To set up GhidraMCP, open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: ghidra
2. Name: GhidraMCP
3. Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

# Building from Source

**Note:** The extension now uses Ghidra's standard build system. You no longer need to manually copy JAR files.

Build and install with Gradle by running:

```bash
./gradlew -PGHIDRA_INSTALL_DIR=/path/to/ghidra install
```

If you omit `install`, gradle will build the plugin in `dist/` but will not install it in Ghidra.

You can also set the `GHIDRA_INSTALL_DIR` environment variable instead of
passing it as a Gradle property:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./gradlew install
```

Or on Windows:

```cmd
set GHIDRA_INSTALL_DIR=C:\path\to\ghidra
gradlew.bat install
```
