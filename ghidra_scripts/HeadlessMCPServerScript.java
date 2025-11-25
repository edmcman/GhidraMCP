// GhidraMCP Headless Server Script
// @category MCP

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.util.task.ConsoleTaskMonitor;
import com.lauriewired.context.HeadlessGhidraContext;
import com.lauriewired.GhidraAnalysisService;
import com.lauriewired.GhidraMCPServer;
import java.util.Optional;

public class HeadlessMCPServerScript extends GhidraScript {
    
    @Override
    public void run() throws Exception {
        Optional.ofNullable(currentProgram)
            .map(program -> new HeadlessGhidraContext(program, new ConsoleTaskMonitor(), state))
            .map(context -> {
                int port = parsePortFromEnv().orElse(8080);
                println("Starting GhidraMCP server for: " + currentProgram.getName());
                println("Listening on port: " + port);
                
                return startServerAndWait(context, port);
            })
            .orElseGet(() -> {
                println("No program loaded. Please load a program first.");
                return false;
            });
    }

    private boolean startServerAndWait(HeadlessGhidraContext context, int port) {
        try {
            GhidraAnalysisService service = new GhidraAnalysisService(context);
            GhidraMCPServer server = new GhidraMCPServer(service, context, port);
            
            server.start();
            println("Server started. Press Ctrl+C to stop.");
            
            waitForCancellation();
            
            server.stop();
            println("Server stopped.");
            return true;
        } catch (Exception e) {
            println("Server error: " + e.getMessage());
            return false;
        }
    }

    private Optional<Integer> parsePortFromEnv() {
        return Optional.ofNullable(System.getenv("GHIDRA_MCP_PORT"))
            .flatMap(this::parseIntSafely);
    }

    private Optional<Integer> parseIntSafely(String value) {
        try {
            return Optional.of(Integer.parseInt(value));
        } catch (NumberFormatException e) {
            println("Invalid port value: " + value + ". Using default.");
            return Optional.empty();
        }
    }

    private void waitForCancellation() throws InterruptedException {
        while (!monitor.isCancelled()) {
            Thread.sleep(1000);
        }
    }
}
