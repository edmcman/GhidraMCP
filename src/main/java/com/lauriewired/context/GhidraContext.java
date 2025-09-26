package com.lauriewired.context;

import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.util.task.TaskMonitor;
import ghidra.app.services.DataTypeManagerService;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Functional interface for abstracting GUI vs headless contexts
 */
@FunctionalInterface
public interface GhidraContext {
    Optional<Program> getCurrentProgram();
    
    default TaskMonitor getTaskMonitor() {
        return TaskMonitor.DUMMY;
    }
    
    default void showMessage(String message) {
        System.out.println(message);
    }
    
    default void showError(String error) {
        System.err.println("ERROR: " + error);
    }
    
    default <T> Optional<T> withProgram(Function<Program, T> operation) {
        return getCurrentProgram().map(operation);
    }
    
    default void ifProgramPresent(Consumer<Program> operation) {
        getCurrentProgram().ifPresent(operation);
    }
    
    // GUI-specific operations with default implementations for headless
    default Optional<Address> getCurrentAddress() {
        return Optional.empty(); // Not available in headless mode
    }
    
    default Optional<String> getCurrentFunction() {
        return Optional.empty(); // Not available in headless mode
    }
    
    default boolean isGuiMode() {
        return false; // Override in GUI context
    }
    
    default Optional<DataTypeManagerService> getDataTypeManagerService() {
        return Optional.empty(); // Not available in headless mode
    }
}
