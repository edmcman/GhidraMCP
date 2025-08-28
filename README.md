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


# Features
MCP Server + Ghidra Plugin/Script

- Decompile and analyze binaries in Ghidra
- Automatically rename methods and data
- List methods, classes, imports, and exports
- **NEW**: Import binary artifacts directly via REST API
- **NEW**: Project status checking and management
- **NEW**: Headless server mode for always-on operation

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
6. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`
7. *Optional*: Configure the port in Ghidra with `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`

## Headless Server Mode

For production environments or always-on operation, you can run the GhidraMCP server in headless mode without the GUI:

### Linux/macOS:
```bash
./start_headless_server.sh /path/to/ghidra_installation [project_path] [port]
```

### Windows:
```batch
start_headless_server.bat "C:\path\to\ghidra_installation" [project_path] [port]
```

**Example:**
```bash
# Linux/macOS
./start_headless_server.sh /Applications/ghidra_10.3.1_PUBLIC ./my_project 8080

# Windows
start_headless_server.bat "C:\ghidra_10.3.1_PUBLIC" "C:\temp\project" 8080
```

The headless server will:
- Start automatically without GUI dependencies
- Create a temporary project if none exists
- Run the HTTP server on the specified port (default: 8080)
- Remain active until manually stopped

**Advantages of headless mode:**
- No GUI dependency - runs on servers without display
- Always available - not tied to CodeBrowser lifecycle
- Scriptable and automatable
- Lower resource usage

**Troubleshooting Headless Mode:**
- Ensure the Ghidra installation path is correct
- Check that Java is available (Ghidra includes its own JDK)
- Verify the script has proper permissions
- Check the log file `ghidra_mcp_server.log` for errors

**Testing the Server:**
```bash
# Test if the server is running
curl http://127.0.0.1:8080/ping

# Check project status
curl http://127.0.0.1:8080/project_status

# List available functions (if a program is loaded)
curl http://127.0.0.1:8080/functions
```

# New Artifact Import API

The plugin now supports importing binary artifacts directly via REST API endpoints:

## Import Endpoints
- **POST** `/import_artifact?filename=<name>` - Upload binary data to import into current project
- **GET** `/project_status` - Check if a project is open and import is available

Example usage:
```bash
# Check project status
curl http://127.0.0.1:8080/project_status

# Import a binary
curl -X POST "http://127.0.0.1:8080/import_artifact?filename=malware.exe" \
     --data-binary @path/to/malware.exe
```

**Requirements**: A Ghidra project must be open for import functionality to work.

## Server Architecture

GhidraMCP provides two ways to run the HTTP server:

### 1. Plugin Mode (GUI-dependent)
- Runs as a Ghidra plugin when CodeBrowser is open
- Automatic startup when plugin is enabled
- Integrated with GUI tool options

### 2. Headless Script Mode (Recommended for production)
- Runs independently of the GUI
- Always available once started
- Better for automation and server deployments
- Can be run via command line scripts

## Migration from Plugin-Only Mode

**Important:** Previous versions required the Ghidra GUI to be open for the HTTP server to be available. This created reliability issues where the server would be unavailable if CodeBrowser wasn't running.

**New Approach:** The headless script mode solves this architectural limitation by running the HTTP server as a standalone Ghidra script, making it available regardless of GUI state.

**Recommended Setup:**
1. For development: Use plugin mode for convenience
2. For production/automation: Use headless script mode for reliability

## MCP Tools
The Python bridge includes corresponding tools:
- `import_artifact(file_path, filename=None)` - Import binary file
- `get_project_status()` - Check project status

## Available API Endpoints

### Core Endpoints
- **GET** `/ping` - Health check and server information
- **GET** `/project_status` - Check if a project is open and import is available
- **POST** `/import_artifact?filename=<name>` - Upload binary data to import into current project

### Analysis Endpoints  
- **GET** `/functions` or `/methods` - List all functions in the current program
- **POST** `/decompile` - Decompile a function by name (send function name in request body)

### Legacy Plugin Endpoints
When running in plugin mode, additional endpoints are available including:
- Variable renaming, cross-references, string analysis, and more
- See the full plugin implementation for complete API reference

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## MCP Clients

Theoretically, any MCP client should work with ghidraMCP.  Three examples are given below.

## Example 1: Claude Desktop
To set up Claude Desktop as a Ghidra MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

Alternatively, edit this file directly:
```
/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json
```

The server IP and port are configurable and should be set to point to the target Ghidra instance. If not set, both will default to localhost:8080.

## Example 2: Cline
To use GhidraMCP with [Cline](https://cline.bot), this requires manually running the MCP server as well. First run the following command:

```
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

The only *required* argument is the transport. If all other arguments are unspecified, they will default to the above. Once the MCP server is running, open up Cline and select `MCP Servers` at the top.

![Cline select](https://github.com/user-attachments/assets/88e1f336-4729-46ee-9b81-53271e9c0ce0)

Then select `Remote Servers` and add the following, ensuring that the url matches the MCP host and port:

1. Server Name: GhidraMCP
2. Server URL: `http://127.0.0.1:8081/sse`

## Example 3: 5ire
Another MCP client that supports multiple models on the backend is [5ire](https://github.com/nanbingxyz/5ire). To set up GhidraMCP, open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: ghidra
2. Name: GhidraMCP
3. Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

# Building from Source
1. Copy the following files from your Ghidra directory to this project's `lib/` directory:
- `Ghidra/Features/Base/lib/Base.jar`
- `Ghidra/Features/Decompiler/lib/Decompiler.jar`
- `Ghidra/Framework/Docking/lib/Docking.jar`
- `Ghidra/Framework/Generic/lib/Generic.jar`
- `Ghidra/Framework/Project/lib/Project.jar`
- `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar`
- `Ghidra/Framework/Utility/lib/Utility.jar`
- `Ghidra/Framework/Gui/lib/Gui.jar`
2. Build with Maven by running:

`mvn clean package assembly:single`

The generated zip file includes the built Ghidra plugin and its resources. These files are required for Ghidra to recognize the new extension.

- lib/GhidraMCP.jar
- extensions.properties
- Module.manifest
