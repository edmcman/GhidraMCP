// GhidraMCP HTTP Server - Standalone Script
// @author LaurieWired & OpenAI GPT
// @category MCP
// @keybinding
// @menupath Tools.MCP.Start MCP Server
// @toolbar ghidra.png

package com.lauriewired;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.Option;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.Msg;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.net.URLDecoder;

/**
 * Standalone GhidraMCP HTTP Server Script
 * 
 * This script runs an HTTP server that provides REST API access to Ghidra functionality
 * without requiring the CodeBrowser to be open. It can be run headlessly or from the GUI.
 * 
 * Usage:
 * 1. From GUI: Run this script via Scripts -> MCP -> GhidraMCPServer.java
 * 2. From command line: Use Ghidra's headless analyzer to run this script
 * 
 * The server will run until the script is stopped or Ghidra exits.
 */
public class GhidraMCPServer extends GhidraScript {
    
    private HttpServer server;
    private static final int DEFAULT_PORT = 8080;
    private boolean serverRunning = false;
    
    @Override
    public void run() throws Exception {
        // Get port from user or use default
        int port = askInt("MCP Server Port", "Enter port number for MCP HTTP server:", DEFAULT_PORT);
        
        try {
            startServer(port);
            println("GhidraMCP HTTP server started on port " + port);
            println("Server will run until script is cancelled or Ghidra exits.");
            println("Use Ctrl+C or stop the script to shut down the server.");
            
            // Keep the script running
            while (!monitor.isCancelled()) {
                Thread.sleep(1000);
            }
            
        } catch (Exception e) {
            printerr("Failed to start GhidraMCP server: " + e.getMessage());
            e.printStackTrace();
        } finally {
            stopServer();
        }
    }
    
    private void startServer(int port) throws IOException {
        if (server != null) {
            println("Stopping existing server...");
            server.stop(0);
        }
        
        server = HttpServer.create(new InetSocketAddress(port), 0);
        
        // Core endpoints from the plugin
        server.createContext("/project_status", this::handleProjectStatus);
        server.createContext("/import_artifact", this::handleImportArtifact);
        server.createContext("/methods", this::handleMethods);
        server.createContext("/decompile", this::handleDecompile);
        server.createContext("/ping", this::handlePing);
        
        // Add basic function listing endpoints
        server.createContext("/functions", this::handleFunctions);
        server.createContext("/list_functions", this::handleFunctions);
        
        server.setExecutor(null);
        server.start();
        serverRunning = true;
        println("HTTP server listening on http://127.0.0.1:" + port);
    }
    
    private void stopServer() {
        if (server != null) {
            println("Stopping GhidraMCP HTTP server...");
            server.stop(1);
            server = null;
            serverRunning = false;
            println("Server stopped.");
        }
    }
    
    // Basic ping endpoint to verify server is running
    private void handlePing(HttpExchange exchange) throws IOException {
        String response = "GhidraMCP Server is running\n" +
                         "Script mode: " + (isRunningHeadless() ? "headless" : "GUI") + "\n" +
                         "Current project: " + (currentProject != null ? currentProject.getName() : "none");
        sendResponse(exchange, response);
    }
    
    // Project status endpoint
    private void handleProjectStatus(HttpExchange exchange) throws IOException {
        try {
            String status = getProjectStatusInfo();
            sendResponse(exchange, status);
        } catch (Exception e) {
            sendResponse(exchange, "Error getting project status: " + e.getMessage());
        }
    }
    
    // Simple methods listing endpoint
    private void handleMethods(HttpExchange exchange) throws IOException {
        handleFunctions(exchange);
    }
    
    // Functions listing endpoint with pagination support
    private void handleFunctions(HttpExchange exchange) throws IOException {
        try {
            if (currentProgram == null) {
                sendResponse(exchange, "No program loaded");
                return;
            }
            
            Map<String, String> queryParams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(queryParams.get("offset"), 0);
            int limit = parseIntOrDefault(queryParams.get("limit"), 100);
            
            List<String> functions = new ArrayList<>();
            currentProgram.getFunctionManager().getFunctions(true).forEach(func -> 
                functions.add(func.getName() + " @ " + func.getEntryPoint())
            );
            
            String result = paginateList(functions, offset, limit);
            sendResponse(exchange, result);
        } catch (Exception e) {
            sendResponse(exchange, "Error listing functions: " + e.getMessage());
        }
    }
    
    // Decompile function endpoint
    private void handleDecompile(HttpExchange exchange) throws IOException {
        try {
            if (currentProgram == null) {
                sendResponse(exchange, "No program loaded");
                return;
            }
            
            String functionName = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            if (functionName == null || functionName.trim().isEmpty()) {
                sendResponse(exchange, "Function name is required");
                return;
            }
            
            String result = decompileFunctionByName(functionName.trim());
            sendResponse(exchange, result);
        } catch (Exception e) {
            sendResponse(exchange, "Error decompiling function: " + e.getMessage());
        }
    }
    
    // Import artifact endpoint
    private void handleImportArtifact(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, "Error: Only POST method supported");
            return;
        }
        
        if (currentProject == null) {
            sendResponse(exchange, "Error: No project is open. Import functionality requires an active project.");
            return;
        }
        
        try {
            // Read the request body
            InputStream requestBody = exchange.getRequestBody();
            byte[] fileData = requestBody.readAllBytes();
            
            if (fileData.length == 0) {
                sendResponse(exchange, "Error: No file data received");
                return;
            }
            
            // Get filename from query parameters or use default
            Map<String, String> queryParams = parseQueryParams(exchange);
            String filename = queryParams.get("filename");
            if (filename == null || filename.trim().isEmpty()) {
                filename = "imported_artifact_" + System.currentTimeMillis();
            }
            
            // Import the artifact
            String result = importArtifactToProject(currentProject, fileData, filename);
            sendResponse(exchange, result);
            
        } catch (Exception e) {
            sendResponse(exchange, "Error importing artifact: " + e.getMessage());
        }
    }
    
    /**
     * Import a binary artifact into the current project using Ghidra's AutoImporter.
     */
    private String importArtifactToProject(Project project, byte[] fileData, String filename) {
        try {
            // Create a temporary file for the import process
            File tempFile = File.createTempFile("ghidra_import_", "_" + filename);
            tempFile.deleteOnExit();
            
            try (FileOutputStream fos = new FileOutputStream(tempFile)) {
                fos.write(fileData);
            }
            
            // Get project data and root folder
            ProjectData projectData = project.getProjectData();
            DomainFolder rootFolder = projectData.getRootFolder();
            
            // Create a message log for import messages
            MessageLog messageLog = new MessageLog();
            
            // Use AutoImporter to import the file
            List<Option> importOptions = new ArrayList<>();
            
            // Perform the import using SwingUtilities to ensure it runs on EDT if needed
            final AtomicBoolean importSuccess = new AtomicBoolean(false);
            final StringBuilder resultMessage = new StringBuilder();
            
            if (isRunningHeadless()) {
                // In headless mode, we can import directly
                performImport(tempFile, rootFolder, filename, importOptions, messageLog, importSuccess, resultMessage);
            } else {
                // In GUI mode, use EDT
                SwingUtilities.invokeAndWait(() -> {
                    performImport(tempFile, rootFolder, filename, importOptions, messageLog, importSuccess, resultMessage);
                });
            }
            
            // Clean up temp file
            tempFile.delete();
            
            return resultMessage.toString();
            
        } catch (Exception e) {
            println("Error importing artifact: " + e.getMessage());
            return "Error importing artifact: " + e.getMessage();
        }
    }
    
    private void performImport(File tempFile, DomainFolder rootFolder, String filename, 
                              List<Option> importOptions, MessageLog messageLog, 
                              AtomicBoolean importSuccess, StringBuilder resultMessage) {
        try {
            List<DomainFile> importedFiles = AutoImporter.importByUsingBestGuess(
                tempFile,           // File to import
                null,               // Project to import into (null = current)
                rootFolder,         // Folder to import into
                null,               // Loader (null = auto-detect)
                filename,           // Program name
                importOptions,      // Import options
                messageLog          // Message log
            );
            
            if (importedFiles != null && !importedFiles.isEmpty()) {
                importSuccess.set(true);
                resultMessage.append("Successfully imported ").append(importedFiles.size()).append(" file(s):\n");
                for (DomainFile file : importedFiles) {
                    resultMessage.append("- ").append(file.getName()).append(" (").append(file.getPathname()).append(")\n");
                }
                
                // If there are any log messages, append them
                if (messageLog.hasMessages()) {
                    resultMessage.append("\nImport messages:\n").append(messageLog.toString());
                }
            } else {
                resultMessage.append("Import failed: No files were imported");
                if (messageLog.hasMessages()) {
                    resultMessage.append("\nError messages:\n").append(messageLog.toString());
                }
            }
        } catch (Exception e) {
            resultMessage.append("Import failed with exception: ").append(e.getMessage());
            if (messageLog.hasMessages()) {
                resultMessage.append("\nError messages:\n").append(messageLog.toString());
            }
        }
    }
    
    private String getProjectStatusInfo() {
        if (currentProject == null) {
            return "Status: No project is currently open\n" +
                   "Import functionality: UNAVAILABLE\n" +
                   "Script mode: " + (isRunningHeadless() ? "headless" : "GUI") + "\n" +
                   "Current program: " + (currentProgram != null ? currentProgram.getName() : "None") + "\n" +
                   "\nTo enable import functionality:\n" +
                   "1. Open or create a Ghidra project\n" +
                   "2. Run this script again";
        }
        
        ProjectData projectData = currentProject.getProjectData();
        String projectName = currentProject.getName();
        String projectLocation = currentProject.getProjectLocator().getLocation();
        int fileCount = projectData.getRootFolder().getFiles().length;
        
        String currentProgramInfo = currentProgram != null ? 
            currentProgram.getName() + " (" + currentProgram.getExecutablePath() + ")" : "None";
        
        return "Status: Project is open\n" +
               "Import functionality: AVAILABLE\n" +
               "Script mode: " + (isRunningHeadless() ? "headless" : "GUI") + "\n" +
               "Project name: " + projectName + "\n" +
               "Project location: " + projectLocation + "\n" +
               "Files in project: " + fileCount + "\n" +
               "Current program: " + currentProgramInfo + "\n" +
               "\nYou can now import artifacts using the /import_artifact endpoint.";
    }
    
    /**
     * Decompile a function by name
     */
    private String decompileFunctionByName(String name) {
        if (currentProgram == null) return "No program loaded";
        
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }
    
    /**
     * Paginate a list of strings
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end = Math.min(items.size(), offset + limit);
        
        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }
    
    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
    
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery();
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        println("Error decoding URL parameter: " + e.getMessage());
                    }
                }
            }
        }
        return result;
    }
    
    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}