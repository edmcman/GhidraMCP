package com.lauriewired.context;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.Optional;

public class HeadlessGhidraContext implements GhidraContext {
    private final Program program;
    private final TaskMonitor monitor;
    
    public HeadlessGhidraContext(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor;
    }
    
    @Override
    public Optional<Program> getCurrentProgram() {
        return Optional.ofNullable(program);
    }
    
    @Override
    public TaskMonitor getTaskMonitor() {
        return monitor;
    }
}
