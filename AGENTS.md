# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

Build and install the Ghidra extension:
```bash
./gradlew -PGHIDRA_INSTALL_DIR=/path/to/ghidra install
```
Or set `GHIDRA_INSTALL_DIR` env var and run `./gradlew install`. Omit `install` to build only (output in `dist/`).

Run the Python MCP bridge:
```bash
python bridge_mcp_ghidra.py [--default-ghidra-server URL] [--transport stdio|sse] [--mcp-host HOST] [--mcp-port PORT] [--enable-headless-tools]
```

Run headless Ghidra analysis:
```bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless /tmp/proj project_name -import /path/to/binary -postScript HeadlessMCPServerScript.java
```

There are no automated tests in this project.

## Architecture

Three-layer design bridging MCP clients to Ghidra's reverse engineering APIs:

```
MCP Client (Claude Desktop, Cline, etc.)
    ↓ MCP protocol (stdio/SSE)
bridge_mcp_ghidra.py (Python FastMCP server)
    ↓ HTTP GET/POST (localhost)
GhidraMCPServer.scala (HTTP server inside Ghidra)
    ↓
GhidraAnalysisService.scala (pure analysis logic)
    ↓
GhidraContext trait → GuiGhidraContext | HeadlessGhidraContext
    ↓
Ghidra APIs (Program, FunctionManager, DecompInterface, etc.)
```

### Key components

- **`GhidraMCPPlugin.scala`** — GUI plugin entry point. Auto-starts HTTP server on random port, creates status panel showing the port.
- **`GhidraMCPServer.scala`** — HTTP server using `com.sun.net.httpserver`. All endpoints are defined here with parameter parsing and response formatting. Delegates to `GhidraAnalysisService`.
- **`GhidraAnalysisService.scala`** — All analysis logic (decompile, rename, list, xrefs, strings, comments, types, scripts, data export). Returns `Either[String, T]` for operations that can fail.
- **`GhidraContext` trait** (`context/GhidraContext.scala`) — Abstracts GUI vs headless execution. `GuiGhidraContext` uses `PluginTool` for program access, navigation, and UI. `HeadlessGhidraContext` wraps a bare `Program` + `TaskMonitor`.
- **`HeadlessMCPServerScript.java`** — Ghidra script for headless mode. Creates `HeadlessGhidraContext`, starts server on configurable port (`GHIDRA_MCP_PORT` env, default 8080).
- **`bridge_mcp_ghidra.py`** — Python FastMCP bridge. Translates MCP tool calls to HTTP requests against the Java server. Manages headless Ghidra processes (`open_artifact_headless`, `close_ghidra_headless`). Handles structured data transformation (e.g., hex→base64+SHA256 for `export_data`).

### Design patterns

- **Context abstraction**: All Ghidra access goes through `GhidraContext` trait. Adding a new execution mode means implementing this trait.
- **Service layer isolation**: `GhidraAnalysisService` is pure logic — no HTTP or UI code. Transactions are managed at service boundaries.
- **HTTP→MCP translation**: The Python bridge is thin — each `@mcp.tool()` calls `safe_get()`/`safe_post()` to hit Java endpoints. Headless process management is the only substantive addition.
- **Dual mode**: GUI (random port, shown in status panel) and headless (configurable port, `analyzeHeadless` + script).

## Language & dependencies

- **Scala 3** (3.6.4) for the Ghidra plugin — uses significant indentation syntax, `Option`-based error handling, pattern matching
- **Java** only for `HeadlessMCPServerScript.java` (Ghidra script API requires Java)
- **Python 3.10+** for the MCP bridge — uses `mcp` SDK (`FastMCP`), `requests`
- **Vavr** (0.10.4) in `lib/` — functional library for Scala/Java
- **Ghidra JARs** in `lib/` — not in git, downloaded by CI from Ghidra 11.3.2
- Extension metadata in `extension.properties` and `Module.manifest`

## CI

GitHub Actions (`.github/workflows/build.yml`): sets up JDK 21, downloads Ghidra 11.3.2, copies 7 JARs to `lib/`, runs `./gradlew buildExtension`, assembles release ZIP with `bridge_mcp_ghidra.py`.