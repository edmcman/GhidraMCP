package com.lauriewired.context;

import ghidra.framework.plugintool.PluginTool;
import ghidra.app.services.ProgramManager;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;
import java.util.Optional;

public class GuiGhidraContext implements GhidraContext {
    private final PluginTool tool;
    
    public GuiGhidraContext(PluginTool tool) {
        this.tool = tool;
    }
    
    @Override
    public Optional<Program> getCurrentProgram() {
        return Optional.ofNullable(tool.getService(ProgramManager.class))
                .map(ProgramManager::getCurrentProgram);
    }
    
    @Override
    public TaskMonitor getTaskMonitor() {
        return TaskMonitor.DUMMY; // Or get from tool if available
    }

    @Override
    public Optional<PluginTool> getTool() {
        return Optional.of(tool);
    }
    
    @Override
    public void showMessage(String message) {
        Msg.info(this, message);
    }
    
    @Override
    public void showError(String error) {
        Msg.error(this, error);
    }
    
    @Override
    public Optional<Address> getCurrentAddress() {
        return Optional.ofNullable(tool.getService(CodeViewerService.class))
                .map(CodeViewerService::getCurrentLocation)
                .map(ProgramLocation::getAddress);
    }
    
    @Override
    public Optional<String> getCurrentFunction() {
        return getCurrentProgram().flatMap(program -> 
            getCurrentAddress().map(addr -> {
                Function func = program.getFunctionManager().getFunctionContaining(addr);
                if (func == null) {
                    return "No function at current location: " + addr;
                }
                return String.format("Function: %s at %s\nSignature: %s",
                    func.getName(), func.getEntryPoint(), func.getSignature());
            })
        );
    }
    
    @Override
    public boolean isGuiMode() {
        return true;
    }
    
    @Override
    public Optional<DataTypeManagerService> getDataTypeManagerService() {
        return Optional.ofNullable(tool.getService(DataTypeManagerService.class));
    }
}
