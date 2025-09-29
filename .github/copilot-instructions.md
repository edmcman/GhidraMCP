# GhidraMCP Copilot Instructions

## Project Overview
GhidraMCP is a Model Context Protocol (MCP) server that exposes Ghidra reverse engineering functionality to LLMs. The architecture bridges Java-based Ghidra analysis with Python MCP clients through a dual-mode system:

- **GUI Mode**: Ghidra plugin (`GhidraMCPPlugin`) with HTTP server
- **Headless Mode**: Command-line analysis via `analyzeHeadless` + script
- **MCP Bridge**: Python client (`bridge_mcp_ghidra.py`) translating HTTP to MCP protocol

## Core Architecture Patterns

### Context Abstraction Pattern
The codebase uses functional interfaces to abstract GUI vs headless execution:

```java
// Core pattern - all operations go through GhidraContext
public interface GhidraContext {
    Optional<Program> getCurrentProgram();
    default <T> Optional<T> withProgram(Function<Program, T> operation) {
        return getCurrentProgram().map(operation);
    }
}
```

**Key implementations:**
- `GuiGhidraContext` - GUI plugin mode with user interactions
- `HeadlessGhidraContext` - Command-line mode with console output

### Service Layer Separation
`GhidraAnalysisService` contains pure analysis logic, isolated from HTTP/GUI concerns:
- Use functional programming style with `Stream` operations
- All methods return `Optional` or collections, never null
- Transaction management handled at service boundaries

### HTTP to MCP Translation
The Python bridge (`bridge_mcp_ghidra.py`) converts between protocols:
- HTTP GET/POST endpoints → MCP tool calls
- Automatic Ghidra process management for headless mode
- Error handling with fallback to default responses

## Development Workflows

### Building from Source
1. **Prerequisites**: Copy Ghidra JARs to `lib/` directory (see README for exact files)
2. **Build**: `mvn clean package assembly:single`
3. **Output**: `target/GhidraMCP-1.0-SNAPSHOT.zip` (Ghidra extension)

### Testing Modes
- **GUI Testing**: Install ZIP in Ghidra, load binary, check `http://localhost:8080/methods`
- **Headless Testing**: Use `analyzeHeadless` with `HeadlessMCPServerScript.java`
- **MCP Testing**: Run `bridge_mcp_ghidra.py` and connect MCP client

### Port Configuration
- GUI: `File → Configure → Developer → GhidraMCP HTTP Server`
- Headless: `GHIDRA_MCP_PORT` environment variable
- MCP Bridge: `--ghidra-server` argument

## Key File Patterns

### Plugin Structure
- `GhidraMCPPlugin.java` - Entry point, lifecycle management
- `GhidraMCPServer.java` - HTTP server with REST endpoints
- `GhidraAnalysisService.java` - Core analysis logic

### Context Implementations
- Extend `GhidraContext` interface for new execution environments
- Use `withProgram()` for operations requiring active program
- Implement proper error handling with `Optional` returns

### Extension Metadata
Required files for Ghidra recognition:
- `extension.properties` - Extension metadata
- `Module.manifest` - Module configuration
- `META-INF/MANIFEST.MF` - JAR manifest

## Integration Points

### Ghidra Dependencies
System-scoped Maven dependencies pointing to `lib/` JARs. Update versions in `pom.xml` when targeting different Ghidra versions.

### MCP Protocol
Python bridge exposes these core tool categories:
- **Analysis**: `get_functions`, `get_classes`, `decompile_*`
- **Modification**: `rename_function`, `set_function_signature`
- **Navigation**: `get_imports`, `get_exports`, `analyze_strings`
- **Headless**: `open_artifact_headless` (auto-starts Ghidra processes)

### Cross-Platform Considerations
- Java HTTP server handles CORS for web clients
- Python bridge supports multiple MCP transports (stdio, SSE)
- File paths use platform-appropriate separators

## Common Debugging Patterns

### Server Connection Issues
1. Check Ghidra plugin is enabled and program loaded
2. Verify port configuration matches client expectations
3. Test direct HTTP endpoints before MCP bridge

### Headless Mode Problems
1. Ensure `GHIDRA_INSTALL_DIR` environment variable is set
2. Check Ghidra script is in `ghidra_scripts/` directory
3. Use `analyzeHeadless` verbose flags for debugging

### MCP Client Integration
1. Test Python bridge standalone first: `python bridge_mcp_ghidra.py --help`
2. Verify server URL in MCP client configuration
3. Use `--enable-headless-tools` for automatic binary analysis