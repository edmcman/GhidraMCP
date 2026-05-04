package com.lauriewired.context

import ghidra.program.model.listing.Program
import ghidra.program.model.address.Address
import ghidra.util.task.TaskMonitor
import ghidra.app.services.DataTypeManagerService
import ghidra.framework.plugintool.PluginTool

trait GhidraContext:
  def getCurrentProgram(): Option[Program]

  def getTaskMonitor(): TaskMonitor = TaskMonitor.DUMMY

  def showMessage(message: String): Unit = println(message)

  def showError(error: String): Unit = System.err.println(s"ERROR: $error")

  def withProgram[T](operation: Program => T): Option[T] =
    getCurrentProgram().map(operation)

  def ifProgramPresent(operation: Program => Unit): Unit =
    getCurrentProgram().foreach(operation)

  def getCurrentAddress(): Option[Address] = None

  def getCurrentFunction(): Option[String] = None

  def isGuiMode(): Boolean = false

  def getDataTypeManagerService(): Option[DataTypeManagerService] = None

  def getTool(): Option[PluginTool] = None
