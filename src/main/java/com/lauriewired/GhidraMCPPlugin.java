package com.lauriewired;

import com.lauriewired.context.GuiGhidraContext;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.options.Options;
import ghidra.util.Msg;
import java.util.Optional;

@PluginInfo(
    status = PluginStatus.RELEASED,
    // The core package is enabled by default. So if we put our plugin in it, it
    // will be enabled by default too!
    packageName = ghidra.app.CorePluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {
    private Optional<GhidraMCPServer> mcpServer = Optional.empty();
    private final GuiGhidraContext context;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        this.context = new GuiGhidraContext(tool);
        
        Msg.info(this, "GhidraMCP Plugin loading...");
        
        registerOptions();
        startServer();  // Start server immediately, regardless of program state
        
        Msg.info(this, "GhidraMCP Plugin loaded!");
    }

    private void startServer() {
        int port = getConfiguredPort();
        
        stopServer(); // Stop existing server if any
        
        try {
            GhidraAnalysisService analysisService = new GhidraAnalysisService(context);
            mcpServer = Optional.of(new GhidraMCPServer(analysisService, context, port));
            mcpServer.ifPresent(server -> {
                try {
                    server.start();
                    context.showMessage("GhidraMCP server started on port " + port);
                } catch (Exception e) {
                    context.showError("Failed to start server: " + e.getMessage());
                }
            });
        } catch (Exception e) {
            context.showError("Server initialization failed: " + e.getMessage());
        }
    }

    private void stopServer() {
        mcpServer.ifPresent(GhidraMCPServer::stop);
        mcpServer = Optional.empty();
    }

    private int getConfiguredPort() {
        return tool.getOptions(OPTION_CATEGORY_NAME)
            .getInt(PORT_OPTION_NAME, DEFAULT_PORT);
    }

    private void registerOptions() {
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT, null,
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");
    }

    @Override
    public void dispose() {
        stopServer();
        Msg.info(this, "GhidraMCP HTTP server stopped.");
        super.dispose();
    }
}
