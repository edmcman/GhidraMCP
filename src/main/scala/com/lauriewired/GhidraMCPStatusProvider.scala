package com.lauriewired

import docking.{ComponentProvider, WindowPosition}
import ghidra.framework.plugintool.PluginTool
import javax.swing.*
import java.awt.*
import java.awt.datatransfer.StringSelection

class GhidraMCPStatusProvider(tool: PluginTool, port: Int)
    extends ComponentProvider(tool, "GhidraMCP Status", "GhidraMCP"):

  private val serverUrl = s"http://127.0.0.1:$port/"
  private val panel = buildPanel()

  setTitle("GhidraMCP Status")
  setDefaultWindowPosition(WindowPosition.BOTTOM)
  setWindowGroup("Core.Bookmarks")
  setIntraGroupPosition(WindowPosition.STACK)

  private def buildPanel(): JComponent =
    val p = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 10))
    p.add(new JLabel("GhidraMCP server:"))
    val urlField = new JTextField(serverUrl, 28)
    urlField.setEditable(false)
    p.add(urlField)
    val copyButton = new JButton("Copy")
    copyButton.addActionListener(_ =>
      Toolkit.getDefaultToolkit.getSystemClipboard
        .setContents(new StringSelection(serverUrl), null)
    )
    p.add(copyButton)
    p

  override def getComponent(): JComponent = panel
