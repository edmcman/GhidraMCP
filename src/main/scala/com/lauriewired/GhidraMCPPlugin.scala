package com.lauriewired

import com.lauriewired.context.GuiGhidraContext
import ghidra.framework.plugintool.{Plugin, PluginTool, PluginInfo}
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.app.plugin.PluginCategoryNames
import ghidra.util.Msg

@PluginInfo(
  status = PluginStatus.RELEASED,
  packageName = ghidra.app.CorePluginPackage.NAME,
  category = PluginCategoryNames.ANALYSIS,
  shortDescription = "HTTP server plugin",
  description = "Starts an embedded HTTP server to expose program data. The bound port is shown in the GhidraMCP Status window."
)
class GhidraMCPPlugin(tool: PluginTool) extends Plugin(tool):
  private var mcpServer: Option[GhidraMCPServer] = None
  private val context = new GuiGhidraContext(tool)
  private var statusProvider: GhidraMCPStatusProvider = null

  Msg.info(this, "GhidraMCP Plugin loading...")
  startServer()
  Msg.info(this, "GhidraMCP Plugin loaded!")

  private def startServer(): Unit =
    stopServer()
    try
      val analysisService = new GhidraAnalysisService(context)
      val server = new GhidraMCPServer(analysisService, context)
      server.start()
      mcpServer = Some(server)
      val port = server.getPort()
      statusProvider = new GhidraMCPStatusProvider(tool, port)
      tool.addComponentProvider(statusProvider, true)
      context.showMessage(s"GhidraMCP server started on port $port")
    catch case e: Exception =>
      context.showError(s"Server initialization failed: ${e.getMessage}")

  private def stopServer(): Unit =
    if statusProvider != null then
      tool.removeComponentProvider(statusProvider)
      statusProvider = null
    mcpServer.foreach(_.stop())
    mcpServer = None

  override def dispose(): Unit =
    stopServer()
    Msg.info(this, "GhidraMCP HTTP server stopped.")
    super.dispose()
