#!/bin/bash

# GhidraMCP Headless Server Launcher
# This script starts the GhidraMCP HTTP server in headless mode

# Check if Ghidra installation path is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <ghidra_install_path> [project_path] [port]"
    echo "Example: $0 /Applications/ghidra_10.3.1_PUBLIC /path/to/project 8080"
    exit 1
fi

GHIDRA_INSTALL_PATH="$1"
PROJECT_PATH="${2:-./tmp_project}"
PORT="${3:-8080}"

# Check if Ghidra installation exists
if [ ! -d "$GHIDRA_INSTALL_PATH" ]; then
    echo "Error: Ghidra installation not found at $GHIDRA_INSTALL_PATH"
    exit 1
fi

echo "Starting GhidraMCP server in headless mode..."
echo "Ghidra path: $GHIDRA_INSTALL_PATH"
echo "Project path: $PROJECT_PATH"
echo "Port: $PORT"

# Create temporary project if it doesn't exist
if [ ! -d "$PROJECT_PATH" ]; then
    echo "Creating temporary project at $PROJECT_PATH"
    mkdir -p "$PROJECT_PATH"
fi

# Set JAVA_HOME if not set (try to use Ghidra's Java)
if [ -z "$JAVA_HOME" ]; then
    if [ -d "$GHIDRA_INSTALL_PATH/support/jdk" ]; then
        export JAVA_HOME="$GHIDRA_INSTALL_PATH/support/jdk"
        echo "Using Ghidra's Java: $JAVA_HOME"
    fi
fi

# Run Ghidra headless with the MCP server script
"$GHIDRA_INSTALL_PATH/support/analyzeHeadless" \
    "$PROJECT_PATH" \
    "MCPProject" \
    -scriptPath "$(dirname "$0")/src/main/java" \
    -postScript GhidraMCPServer.java \
    -scriptlog "ghidra_mcp_server.log" \
    -noanalysis