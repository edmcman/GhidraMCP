package com.lauriewired;

import com.lauriewired.context.GuiGhidraContext;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.util.Msg;
import java.util.Optional;

@PluginInfo(
    status = PluginStatus.RELEASED,
    // The core package is enabled by default. So if we put our plugin in it, it
    // will be enabled by default too!
    packageName = ghidra.app.CorePluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. The bound port is shown in the GhidraMCP Status window."
)
public class GhidraMCPPlugin extends Plugin {
    private Optional<GhidraMCPServer> mcpServer = Optional.empty();
    private final GuiGhidraContext context;
    private GhidraMCPStatusProvider statusProvider;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        this.context = new GuiGhidraContext(tool);

        Msg.info(this, "GhidraMCP Plugin loading...");
        startServer();
        Msg.info(this, "GhidraMCP Plugin loaded!");
    }

    private void startServer() {
        stopServer();

        try {
            GhidraAnalysisService analysisService = new GhidraAnalysisService(context);
            GhidraMCPServer server = new GhidraMCPServer(analysisService, context);
            server.start();
            mcpServer = Optional.of(server);
            int port = server.getPort();
            statusProvider = new GhidraMCPStatusProvider(tool, port);
            tool.addComponentProvider(statusProvider, true);
            context.showMessage("GhidraMCP server started on port " + port);
        } catch (Exception e) {
            context.showError("Server initialization failed: " + e.getMessage());
        }
    }

    private void stopServer() {
        if (statusProvider != null) {
            tool.removeComponentProvider(statusProvider);
            statusProvider = null;
        }
        mcpServer.ifPresent(GhidraMCPServer::stop);
        mcpServer = Optional.empty();
    }

    @Override
    public void dispose() {
        stopServer();
        Msg.info(this, "GhidraMCP HTTP server stopped.");
        super.dispose();
    }
}
