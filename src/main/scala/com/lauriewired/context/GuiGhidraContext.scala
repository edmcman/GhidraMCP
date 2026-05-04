package com.lauriewired.context

import ghidra.framework.plugintool.PluginTool
import ghidra.app.services.{ProgramManager, CodeViewerService, DataTypeManagerService}
import ghidra.program.model.listing.Program
import ghidra.program.model.address.Address
import ghidra.util.task.TaskMonitor
import ghidra.util.Msg

class GuiGhidraContext(tool: PluginTool) extends GhidraContext:
  override def getCurrentProgram(): Option[Program] =
    Option(tool.getService(classOf[ProgramManager])).map(_.getCurrentProgram)

  override def getTaskMonitor(): TaskMonitor = TaskMonitor.DUMMY

  override def getTool(): Option[PluginTool] = Some(tool)

  override def showMessage(message: String): Unit = Msg.info(this, message)

  override def showError(error: String): Unit = Msg.error(this, error)

  override def getCurrentAddress(): Option[Address] =
    Option(tool.getService(classOf[CodeViewerService]))
      .flatMap(svc => Option(svc.getCurrentLocation))
      .map(_.getAddress)

  override def getCurrentFunction(): Option[String] =
    for
      program <- getCurrentProgram()
      addr    <- getCurrentAddress()
    yield
      val func = program.getFunctionManager().getFunctionContaining(addr)
      if func == null then s"No function at current location: $addr"
      else s"Function: ${func.getName} at ${func.getEntryPoint}\nSignature: ${func.getSignature}"

  override def isGuiMode(): Boolean = true

  override def getDataTypeManagerService(): Option[DataTypeManagerService] =
    Option(tool.getService(classOf[DataTypeManagerService]))
