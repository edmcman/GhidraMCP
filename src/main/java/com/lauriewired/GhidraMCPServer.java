package com.lauriewired;

import com.lauriewired.context.GhidraContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * HTTP server wrapper that exposes GhidraAnalysisService functionality via REST
 * endpoints.
 * This class is shared between GUI and headless modes.
 */
public class GhidraMCPServer {
    private HttpServer server;
    private final GhidraAnalysisService analysisService;
    private final GhidraContext context;
    private final int port;

    public GhidraMCPServer(GhidraAnalysisService analysisService, GhidraContext context, int port) {
        this.analysisService = analysisService;
        this.context = context;
        this.port = port;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        setupEndpoints();
        server.setExecutor(null);
        server.start();
    }

    private void sendJsonResponse(HttpExchange exchange, Map<String, Object> response) throws IOException {
        // Simple JSON serialization - in production use a proper JSON library
        StringBuilder json = new StringBuilder();
        json.append("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : response.entrySet()) {
            if (!first)
                json.append(",");
            json.append("\"").append(entry.getKey()).append("\":");
            Object value = entry.getValue();
            if (value instanceof String) {
                json.append("\"").append(value).append("\"");
            } else if (value instanceof Boolean) {
                json.append(value);
            } else {
                json.append("\"").append(value.toString()).append("\"");
            }
            first = false;
        }
        json.append("}");

        byte[] bytes = json.toString().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    public void stop() {
        if (server != null) {
            server.stop(1);
            server = null;
            System.out.println("GhidraMCP HTTP server stopped");
        }
    }

    private void setupEndpoints() {
        // Function listing endpoints
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);

            List<String> result = analysisService.getAllFunctionNames(offset, limit);
            sendResponse(exchange, String.join("\n", result));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);

            List<String> result = analysisService.getAllClassNames(offset, limit);
            sendResponse(exchange, String.join("\n", result));
        });

        // Decompilation endpoints
        server.createContext("/decompile", exchange -> {
            byte[] body = readAllBytes(exchange.getRequestBody());
            String name = new String(body, StandardCharsets.UTF_8);
            sendResponse(exchange, analysisService.decompileFunctionByName(name));
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, analysisService.decompileFunctionByAddress(address));
        });

        // Function renaming endpoints
        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean success = analysisService.renameFunction(
                    params.get("oldName"), params.get("newName"));
            sendResponse(exchange, success ? "Renamed successfully" : "Rename failed");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean success = analysisService.renameFunctionByAddress(
                    params.get("function_address"), params.get("new_name"));
            sendResponse(exchange, success ? "Renamed successfully" : "Rename failed");
        });

        // Listing endpoints
        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);

            List<String> result = analysisService.listSegments(offset, limit);
            sendResponse(exchange, String.join("\n", result));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);

            List<String> result = analysisService.listImports(offset, limit);
            sendResponse(exchange, String.join("\n", result));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);

            List<String> result = analysisService.listExports(offset, limit);
            sendResponse(exchange, String.join("\n", result));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);

            List<String> result = analysisService.listNamespaces(offset, limit);
            sendResponse(exchange, String.join("\n", result));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);

            List<String> result = analysisService.searchFunctionsByName(searchTerm, offset, limit);
            sendResponse(exchange, String.join("\n", result));
        });

        // Additional endpoints that were missing
        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);

            List<String> result = analysisService.listDefinedData(offset, limit);
            sendResponse(exchange, String.join("\n", result));
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean success = analysisService.renameDataAtAddress(
                    params.get("address"), params.get("newName"));
            sendResponse(exchange, success ? "Data renamed successfully" : "Failed to rename data");
        });

        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, analysisService.getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, analysisService.getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, analysisService.getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);

            List<String> result = analysisService.listFunctions(offset, limit);
            sendResponse(exchange, String.join("\n", result));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, analysisService.disassembleFunction(address));
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);

            List<String> result = analysisService.getXrefsTo(address, offset, limit);
            sendResponse(exchange, String.join("\n", result));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);

            List<String> result = analysisService.getXrefsFrom(address, offset, limit);
            sendResponse(exchange, String.join("\n", result));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionName = qparams.get("function_name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);

            List<String> result = analysisService.getFunctionXrefs(functionName, offset, limit);
            sendResponse(exchange, String.join("\n", result));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);

            List<String> result = analysisService.getStrings(offset, limit);
            sendResponse(exchange, String.join("\n", result));
        });

        // Additional advanced endpoints
        // =============================

        server.createContext("/run_script", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parsePostParams(exchange);
                String script = params.get("script");
                String result = analysisService.runScript(script);
                sendResponse(exchange, String.join("\n", result));
            }
        });

        // Data export endpoint
        server.createContext("/export_functions", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                String result = analysisService.exportFunctions();
                Map<String, Object> response = new HashMap<>();
                response.put("functions", result);
                sendJsonResponse(exchange, response);
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        // Comment endpoints
        server.createContext("/set_decompiler_comment", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parsePostParams(exchange);
                String address = params.get("address");
                String comment = params.get("comment");

                boolean success = analysisService.setDecompilerComment(address, comment);
                Map<String, Object> response = new HashMap<>();
                response.put("success", success);
                sendJsonResponse(exchange, response);
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parsePostParams(exchange);
                String address = params.get("address");
                String comment = params.get("comment");

                boolean success = analysisService.setDisassemblyComment(address, comment);
                Map<String, Object> response = new HashMap<>();
                response.put("success", success);
                sendJsonResponse(exchange, response);
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        // Variable operations
        server.createContext("/rename_variable", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parsePostParams(exchange);
                String functionName = params.get("function");
                String oldName = params.get("old_name");
                String newName = params.get("new_name");

                String result = analysisService.renameVariableInFunction(functionName, oldName, newName);
                Map<String, Object> response = new HashMap<>();
                response.put("result", result);
                sendJsonResponse(exchange, response);
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        // Legacy endpoint alias
        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("function");
            String oldName = params.get("old_name");
            String newName = params.get("new_name");

            String result = analysisService.renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/set_local_variable_type", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parsePostParams(exchange);
                String functionAddress = params.get("function_address");
                String variableName = params.get("variable_name");
                String newType = params.get("new_type");

                String result = analysisService.setLocalVariableType(functionAddress, variableName, newType);
                sendResponse(exchange, result);
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        // Function prototype operations
        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            if (functionAddress == null || prototype == null) {
                sendResponse(exchange, "Error: function_address and prototype parameters are required");
                return;
            }

            String result = analysisService.setFunctionPrototype(functionAddress, prototype);
            sendResponse(exchange, result);
        });

        // Data export operations
        server.createContext("/export_data", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                String address = qparams.get("address");
                String lengthStr = qparams.get("length");

                if (address == null || lengthStr == null) {
                    sendResponse(exchange, "Error: address and length parameters are required");
                    return;
                }

                try {
                    int length = Integer.parseInt(lengthStr);
                    String result = analysisService.exportData(address, length);
                    sendResponse(exchange, result);
                } catch (NumberFormatException e) {
                    sendResponse(exchange, "Error: Invalid length parameter: " + lengthStr);
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        });

        // Type creation operations
        server.createContext("/create_type_from_c_definition", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String cDefinition = params.get("definition");

            String result = analysisService.createTypeFromCDefinition(cDefinition);
            sendResponse(exchange, result);
        });
    }

    // Utility Methods
    // ===============

    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery();
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8.name());
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8.name());
                        result.put(key, value);
                    } catch (Exception e) {
                        System.err.println("Error decoding URL parameter: " + e.getMessage());
                    }
                }
            }
        }
        return result;
    }

    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = readAllBytes(exchange.getRequestBody());
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8.name());
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8.name());
                    params.put(key, value);
                } catch (Exception e) {
                    System.err.println("Error decoding POST parameter: " + e.getMessage());
                }
            }
        }
        return params;
    }

    private byte[] readAllBytes(InputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[1024];
        while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        buffer.flush();
        return buffer.toByteArray();
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null || val.trim().isEmpty()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(val.trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}
