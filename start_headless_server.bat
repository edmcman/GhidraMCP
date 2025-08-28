@echo off
REM GhidraMCP Headless Server Launcher for Windows
REM This script starts the GhidraMCP HTTP server in headless mode

if "%1"=="" (
    echo Usage: %0 ^<ghidra_install_path^> [project_path] [port]
    echo Example: %0 "C:\ghidra_10.3.1_PUBLIC" "C:\temp\project" 8080
    exit /b 1
)

set GHIDRA_INSTALL_PATH=%1
set PROJECT_PATH=%2
set PORT=%3

if "%PROJECT_PATH%"=="" set PROJECT_PATH=.\tmp_project
if "%PORT%"=="" set PORT=8080

REM Check if Ghidra installation exists
if not exist "%GHIDRA_INSTALL_PATH%" (
    echo Error: Ghidra installation not found at %GHIDRA_INSTALL_PATH%
    exit /b 1
)

echo Starting GhidraMCP server in headless mode...
echo Ghidra path: %GHIDRA_INSTALL_PATH%
echo Project path: %PROJECT_PATH%
echo Port: %PORT%

REM Create temporary project if it doesn't exist
if not exist "%PROJECT_PATH%" (
    echo Creating temporary project at %PROJECT_PATH%
    mkdir "%PROJECT_PATH%"
)

REM Set JAVA_HOME if not set (try to use Ghidra's Java)
if "%JAVA_HOME%"=="" (
    if exist "%GHIDRA_INSTALL_PATH%\support\jdk" (
        set JAVA_HOME=%GHIDRA_INSTALL_PATH%\support\jdk
        echo Using Ghidra's Java: %JAVA_HOME%
    )
)

REM Run Ghidra headless with the MCP server script
"%GHIDRA_INSTALL_PATH%\support\analyzeHeadless.bat" ^
    "%PROJECT_PATH%" ^
    "MCPProject" ^
    -scriptPath "%~dp0src\main\java" ^
    -postScript GhidraMCPServer.java ^
    -scriptlog "ghidra_mcp_server.log" ^
    -noanalysis