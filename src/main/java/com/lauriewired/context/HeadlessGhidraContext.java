package com.lauriewired.context;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.app.script.GhidraState;
import java.util.Optional;

public class HeadlessGhidraContext implements GhidraContext {
    private final Program program;
    private final TaskMonitor monitor;
    private final GhidraState scriptState;
    
    public HeadlessGhidraContext(Program program, TaskMonitor monitor) {
        this(program, monitor, null);
    }
    
    public HeadlessGhidraContext(Program program, TaskMonitor monitor, GhidraState scriptState) {
        this.program = program;
        this.monitor = monitor;
        this.scriptState = scriptState;
    }
    
    @Override
    public Optional<Program> getCurrentProgram() {
        return Optional.ofNullable(program);
    }
    
    @Override
    public TaskMonitor getTaskMonitor() {
        return monitor;
    }

    @Override
    public Optional<GhidraState> getScriptState() {
        return Optional.ofNullable(scriptState);
    }
}
