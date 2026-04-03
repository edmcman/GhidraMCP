package com.lauriewired;

import docking.ComponentProvider;
import docking.WindowPosition;
import ghidra.framework.plugintool.PluginTool;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

public class GhidraMCPStatusProvider extends ComponentProvider {

    private final String serverUrl;
    private JComponent panel;

    public GhidraMCPStatusProvider(PluginTool tool, int port) {
        super(tool, "GhidraMCP Status", "GhidraMCP");
        this.serverUrl = "http://127.0.0.1:" + port + "/";
        setTitle("GhidraMCP Status");
        setDefaultWindowPosition(WindowPosition.BOTTOM);
        setWindowGroup("Core.Bookmarks");
        setIntraGroupPosition(WindowPosition.STACK);
        buildPanel();
    }

    private void buildPanel() {
        panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 10));
        panel.add(new JLabel("GhidraMCP server:"));
        JTextField urlField = new JTextField(serverUrl, 28);
        urlField.setEditable(false);
        panel.add(urlField);
        JButton copyButton = new JButton("Copy");
        copyButton.addActionListener(e ->
            Toolkit.getDefaultToolkit()
                .getSystemClipboard()
                .setContents(new StringSelection(serverUrl), null)
        );
        panel.add(copyButton);
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }
}
