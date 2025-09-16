# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
import hashlib
import os
import subprocess
import time
import signal
import tempfile
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

# Global variables to track the current Ghidra headless process
current_ghidra_process = None
current_project_dir = None

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def kill_existing_ghidra_processes():
    """Kill any existing analyzeHeadless processes using global process tracking."""
    global current_ghidra_process
    killed_count = 0
    
    if current_ghidra_process is not None:
        try:
            if current_ghidra_process.poll() is None:  # Process is still running
                logger.info(f"Killing tracked Ghidra process {current_ghidra_process.pid}")
                current_ghidra_process.terminate()
                try:
                    current_ghidra_process.wait(timeout=5)  # Wait up to 5 seconds for graceful termination
                except subprocess.TimeoutExpired:
                    logger.warning("Process didn't terminate gracefully, forcing kill")
                    current_ghidra_process.kill()
                    current_ghidra_process.wait()
                killed_count += 1
            current_ghidra_process = None
        except (OSError, subprocess.SubprocessError) as e:
            logger.warning(f"Error killing tracked process: {e}")
            current_ghidra_process = None
    
    return killed_count

def wait_for_ghidra_server(max_wait_time=60):
    """Wait for the Ghidra MCP server to become available."""
    start_time = time.time()
    while time.time() - start_time < max_wait_time:
        try:
            response = requests.get(urljoin(ghidra_server_url, "methods"), timeout=2)
            if response.ok:
                logger.info("Ghidra MCP server is ready")
                return True
        except:
            pass
        time.sleep(1)
    return False

def get_ghidra_install_dir():
    """Get the Ghidra installation directory from environment."""
    ghidra_dir = os.environ.get('GHIDRA_INSTALL_DIR')
    if not ghidra_dir:
        raise ValueError("GHIDRA_INSTALL_DIR environment variable is not set")
    if not os.path.exists(ghidra_dir):
        raise ValueError(f"GHIDRA_INSTALL_DIR path does not exist: {ghidra_dir}")
    analyze_headless = os.path.join(ghidra_dir, "support", "analyzeHeadless")
    if not os.path.exists(analyze_headless):
        raise ValueError(f"analyzeHeadless not found at: {analyze_headless}")
    return analyze_headless

def check_headless_tools_enabled() -> str | None:
    """
    Check if headless tools are enabled and return an error message if not.
    
    Returns:
        Error message string if headless tools are disabled, None if enabled
    """
    if not headless_tools_enabled:
        return "Error: Headless tools are not enabled. Use --enable-headless-tools flag when starting the server."
    return None

# Global flag to track if headless tools are enabled
headless_tools_enabled = False

@mcp.tool()
def open_artifact_headless(artifact_path: str) -> str:
    """
    Open an artifact in Ghidra headless mode and start the MCP server.
    This will kill any existing Ghidra processes and start a new one.
    Uses the port from the current ghidra_server_url configuration.
    
    Args:
        artifact_path: Path to the binary/artifact to analyze
        
    Returns:
        Status message indicating success or failure
    """
    error_msg = check_headless_tools_enabled()
    if error_msg:
        return error_msg
    
    global current_ghidra_process, current_project_dir, ghidra_server_url
    
    try:
        # Validate artifact path
        if not os.path.exists(artifact_path):
            return f"Error: Artifact not found: {artifact_path}"
        
        # Extract port from current ghidra_server_url
        from urllib.parse import urlparse
        parsed_url = urlparse(ghidra_server_url)
        port = parsed_url.port or 8080  # Default to 8080 if no port specified
        
        # Get Ghidra installation
        try:
            analyze_headless = get_ghidra_install_dir()
        except ValueError as e:
            return f"Error: {str(e)}"
        
        # Kill existing processes
        killed_count = kill_existing_ghidra_processes()
        if killed_count > 0:
            logger.info(f"Killed {killed_count} existing Ghidra process(es)")
            time.sleep(2)  # Give processes time to fully terminate
        
        # Clean up old process reference
        if current_ghidra_process:
            current_ghidra_process = None
        
        # Create temporary project directory
        if current_project_dir and os.path.exists(current_project_dir):
            import shutil
            shutil.rmtree(current_project_dir, ignore_errors=True)
        
        current_project_dir = tempfile.mkdtemp(prefix="ghidra_mcp_")
        project_name = f"mcp_project_{int(time.time())}"
        
        # Prepare environment - use the port from the configured server URL
        env = os.environ.copy()
        env['GHIDRA_MCP_PORT'] = str(port)
        
        # Build command
        cmd = [
            analyze_headless,
            current_project_dir,
            project_name,
            "-overwrite",
            "-import", artifact_path,
            "-postScript", "HeadlessMCPServerScript.java"
        ]
        
        logger.info(f"Starting Ghidra headless analysis: {' '.join(cmd)}")
        
        # Start the process
        current_ghidra_process = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait for server to become available
        logger.info("Waiting for Ghidra MCP server to start...")
        if wait_for_ghidra_server():
            return f"Successfully opened {artifact_path} in Ghidra headless mode at {ghidra_server_url}"
        else:
            logger.error("Timed out waiting for Ghidra MCP server to start")
            ret = current_ghidra_process.poll()

            # Check if process is still running
            if ret is not None:
                return f"Error: Ghidra process exited unexpectedly. Exit: {ret}"
            else:
                stdout, stderr = current_ghidra_process.communicate()
                return f"Warning: Ghidra process started but MCP server did not become available at {ghidra_server_url}. Stdout: {stdout}, Stderr: {stderr}"
        
    except Exception as e:
        return f"Error starting Ghidra headless mode: {str(e)}"

@mcp.tool()
def close_ghidra_headless() -> str:
    """
    Close the current Ghidra headless process.
    
    Returns:
        Status message indicating success or failure
    """
    error_msg = check_headless_tools_enabled()
    if error_msg:
        return error_msg
    
    global current_ghidra_process, current_project_dir
    
    try:
        killed_count = kill_existing_ghidra_processes()
        
        if current_ghidra_process:
            current_ghidra_process = None
        
        if current_project_dir and os.path.exists(current_project_dir):
            import shutil
            shutil.rmtree(current_project_dir, ignore_errors=True)
            current_project_dir = None
        
        if killed_count > 0:
            return f"Successfully closed Ghidra headless process(es) ({killed_count} killed)"
        else:
            return "No Ghidra headless processes were running"
        
    except Exception as e:
        return f"Error closing Ghidra headless process: {str(e)}"

@mcp.tool()
def get_ghidra_status() -> str:
    """
    Get the status of the current Ghidra headless process and server.
    
    Returns:
        Status information about the Ghidra process and MCP server
    """
    error_msg = check_headless_tools_enabled()
    if error_msg:
        return error_msg
    
    global current_ghidra_process
    
    try:
        # Check if we have a tracked process
        process_status = "No tracked process"
        if current_ghidra_process:
            if current_ghidra_process.poll() is None:
                process_status = f"Process running (PID: {current_ghidra_process.pid})"
            else:
                process_status = f"Process exited (return code: {current_ghidra_process.returncode})"
        
        # Check server connectivity
        try:
            response = requests.get(urljoin(ghidra_server_url, "methods"), timeout=2)
            server_status = f"MCP server reachable at {ghidra_server_url}" if response.ok else f"MCP server not responding at {ghidra_server_url}"
        except:
            server_status = f"MCP server not reachable at {ghidra_server_url}"
        
        status_lines = [
            f"Tracked process: {process_status}",
            f"Server: {server_status}",
            f"Project directory: {current_project_dir or 'None'}"
        ]
        
        return "\n".join(status_lines)
        
    except Exception as e:
        return f"Error getting status: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions(offset: int = 0, limit: int = 100) -> list:
    """
    List all functions in the database with pagination.
    """
    return safe_get("list_functions", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type by its name.

    Args:
        function_address: Target address in hex format (e.g. "0x1400010a0")
        variable_name: Name of variable to retype (e.g. "var_c")
        new_type: Name of new type (e.g. "Point")
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def create_type_from_c_definition(c_definition: str) -> str:
    """
    Create a data type from its C definition string.
    
    Args:
        c_definition: The C definition as a string (e.g., "struct Point { int x; int y; };")
        
    Returns:
        Result of the type creation operation
    """
    return safe_post("create_type_from_c_definition", c_definition)

@mcp.tool()
def export_data(address: str, length: int) -> dict:
    """
    Export raw data from memory at the specified address with SHA256 hash for verification.
    
    Args:
        address: Address in hex format (e.g. "0x1400010a0")
        length: Number of bytes to export
        
    Returns:
        Dictionary containing hex data and SHA256 hash for verification
    """
    result = safe_get("export_data", {"address": address, "length": str(length)})
    hex_data = "".join(result)

    # If it's an error message, return it as-is
    if hex_data.startswith("Error: "):
        return {"error": hex_data}

    try:
        # Convert hex string to raw bytes
        raw_bytes = bytes.fromhex(hex_data)
        
        # Calculate SHA256 hash
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        
        # Return structured data with separate fields
        return {
            "data": raw_bytes,
            "sha256": sha256_hash,
        }
        
    except Exception as e:
        return {"error": f"Error processing hex data: {str(e)}"}

def cleanup_ghidra_processes():
    """Clean up any tracked Ghidra processes and temp directories."""
    global current_ghidra_process, current_project_dir
    
    try:
        if current_ghidra_process:
            current_ghidra_process = None
        
        if current_project_dir and os.path.exists(current_project_dir):
            import shutil
            shutil.rmtree(current_project_dir, ignore_errors=True)
            current_project_dir = None
            
        # Kill any remaining analyzeHeadless processes
        kill_existing_ghidra_processes()
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")

def signal_handler(signum, frame):
    """Handle signals for graceful shutdown."""
    logger.info("Received shutdown signal, cleaning up...")
    cleanup_ghidra_processes()
    sys.exit(0)

def main():
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    parser.add_argument("--enable-headless-tools", action="store_true",
                        help="Enable headless tools (open_artifact_headless, close_ghidra_headless, get_ghidra_status)")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    # Register headless tools if enabled
    if args.enable_headless_tools:
        logger.info("Enabling headless tools")
        global headless_tools_enabled
        headless_tools_enabled = True
    else:
        logger.info("Headless tools disabled (use --enable-headless-tools to enable)")
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
            cleanup_ghidra_processes()
        finally:
            cleanup_ghidra_processes()
    else:
        try:
            mcp.run()
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
            cleanup_ghidra_processes()
        finally:
            cleanup_ghidra_processes()
        
if __name__ == "__main__":
    main()

