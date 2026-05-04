package com.lauriewired.context

import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor

class HeadlessGhidraContext(program: Program, monitor: TaskMonitor) extends GhidraContext:
  override def getCurrentProgram(): Option[Program] = Option(program)
  override def getTaskMonitor(): TaskMonitor = monitor
