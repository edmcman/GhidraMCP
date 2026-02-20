package com.lauriewired;

import com.lauriewired.context.GhidraContext;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.data.*;
import ghidra.app.decompiler.*;
import ghidra.app.services.GoToService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.*;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import generic.jar.ResourceFile;
import io.vavr.control.Either;
import java.util.*;
import java.io.*;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import java.util.stream.Collectors;

/**
 * Core Ghidra analysis service with functional programming approach.
 * Contains all analysis logic separated from GUI/HTTP concerns.
 */
public class GhidraAnalysisService {
    private final GhidraContext context;

    public GhidraAnalysisService(GhidraContext context) {
        this.context = context;
    }

    // Core Analysis Methods
    // =====================

    /**
     * Runs a Ghidra script by writing the provided source code to a script file, 
     * instantiating and executing it, and returning its output.
     * <p>
     * The script is created in the user's script directory, loaded and executed with the current Ghidra state.
     * After execution, the script file is deleted.
     *
     * @param scriptName   the name of the script file to create and execute (e.g., "MyScript.java")
     * @param scriptSource the source code of the script to execute
     * @return the output produced by the script, or an error message if execution fails
     * @throws IOException if there is an error writing the script file (caught and returned as error message)
     * @throws Exception   if there is an error during script instantiation or execution (caught and returned as error message)
     */
    public String runScript(String scriptName, String scriptSource) {
        return createScriptFile(scriptName, scriptSource)
            .flatMap(scriptFile -> loadScript(scriptFile))
            .flatMap(script -> executeScript(script, scriptName))
            .fold(error -> error, output -> output);
    }

    private Either<String, ResourceFile> createScriptFile(String scriptName, String scriptSource) {
        try {
            ResourceFile scriptDir = GhidraScriptUtil.getUserScriptDirectory();
            File scriptFile = new File(scriptDir.getFile(false), scriptName);
            try (FileWriter writer = new FileWriter(scriptFile)) {
                writer.write(scriptSource);
            }
            return Either.right(new ResourceFile(scriptFile));
        } catch (IOException e) {
            Msg.error(this, "Error writing script file: " + e.getMessage());
            return Either.left("Failed to create script file: " + e.getMessage());
        }
    }

    private Either<String, GhidraScript> loadScript(ResourceFile scriptFile) {
        return java.util.stream.IntStream.range(0, 3)
            .mapToObj(attempt -> {
                try {
                    if (attempt > 0) {
                        Thread.sleep(1000);
                    }
                    GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
                    return Either.<String, GhidraScript>right(provider.getScriptInstance(scriptFile, new PrintWriter(System.err)));
                } catch (Exception e) {
                    Msg.error(this, "Script load attempt " + (attempt + 1) + " failed: " + e.getMessage());
                    return Either.<String, GhidraScript>left(e.getMessage());
                }
            })
            .reduce((a, b) -> a.isRight() ? a : b)
            .orElse(Either.left("No attempts made"));
    }

    private Either<String, String> executeScript(GhidraScript script, String scriptName) {
        try {
            StringWriter stringWriter = new StringWriter();
            PrintWriter outWriter = new PrintWriter(stringWriter);
            script.execute(getState(), TaskMonitor.DUMMY, outWriter);
            return Either.right(stringWriter.toString());
        } catch (Exception e) {
            return Either.left("Error running script: " + e.getMessage());
        } finally {
            cleanupScriptFile(scriptName);
        }
    }

    private void cleanupScriptFile(String scriptName) {
        try {
            // Delete the temporary script file after execution to avoid leaving orphaned files.
            ResourceFile scriptFile = GhidraScriptUtil.findScriptByName(scriptName);
            if (scriptFile != null && scriptFile.exists()) {
                scriptFile.delete();
            }
        } catch (Exception e) {
            Msg.error(this, "Error cleaning up script file: " + e.getMessage());
        }
    }

    private GhidraState getState() {
        Program currentProgram = context.getCurrentProgram().orElse(null);
        Address currentAddress = context.getCurrentAddress().orElse(null);
        ProgramLocation loc = (currentProgram != null && currentAddress != null)
                ? new ProgramLocation(currentProgram, currentAddress)
                : null;
        PluginTool tool = context.getTool().orElse(null);
        Project project = tool != null ? tool.getProject() : null;
        return new GhidraState(tool, project, currentProgram, loc, null, null);
    }

    public Either<String, List<String>> getAllFunctionNames(int offset, int limit) {
        return context.<Either<String, List<String>>>withProgram(program -> 
            Either.<String, List<String>>right(
                streamFunctions(program)
                    .map(Function::getName)
                    .skip(offset)
                    .limit(limit)
                    .collect(Collectors.toList())
            )
        ).orElse(Either.left("No program loaded"));
    }

    public Either<String, List<String>> getAllClassNames(int offset, int limit) {
        return context.<Either<String, List<String>>>withProgram(program -> {
            Set<String> classNames = new HashSet<>();
            for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
                Namespace ns = symbol.getParentNamespace();
                if (ns != null && !ns.isGlobal()) {
                    classNames.add(ns.getName());
                }
            }
            List<String> result = new ArrayList<>(classNames).stream()
                .sorted()
                .skip(offset)
                .limit(limit)
                .collect(Collectors.toList());
            return Either.right(result);
        }).orElse(Either.left("No program loaded"));
    }

    public String decompileFunctionByName(String name) {
        return context.<String>withProgram(program -> 
            findFunctionByName(program, name)
                .flatMap(func -> decompileFunction(program, func))
                .fold(err -> "Function not found: " + err, output -> output)
        ).orElse("No program loaded");
    }

    public String decompileFunctionByAddress(String addressStr) {
        return context.<String>withProgram(program -> 
            parseAddress(program, addressStr)
                .flatMap(addr -> findFunctionByAddress(program, addr))
                .flatMap(func -> decompileFunction(program, func))
                .fold(err -> "Function not found at address: " + err, output -> output)
        ).orElse("No program loaded");
    }

    public Either<String, String> renameFunction(String oldName, String newName) {
        return context.<Either<String, String>>withProgram(program -> {
            int tx = program.startTransaction("Rename function");
            try {
                return findFunctionByName(program, oldName)
                    .flatMap(func -> {
                        try {
                            boolean ok = tryRename(func, newName);
                            return ok ? Either.right("Renamed successfully") : Either.left("Failed to rename function");
                        } catch (Exception e) {
                            return Either.left("Failed to rename function: " + e.getMessage());
                        }
                    })
                    .orElse(Either.left("Function '" + oldName + "' not found"));
            } finally {
                program.endTransaction(tx, true);
            }
        }).orElse(Either.left("No program loaded"));
    }

    public Either<String, String> renameFunctionByAddress(String addressStr, String newName) {
        return context.<Either<String, String>>withProgram(program -> {
            int tx = program.startTransaction("Rename function by address");
            try {
                return parseAddress(program, addressStr)
                    .flatMap(addr -> findFunctionByAddress(program, addr))
                    .flatMap(func -> {
                        try {
                            boolean ok = tryRename(func, newName);
                            return ok ? Either.right("Renamed successfully") : Either.left("Failed to rename function");
                        } catch (Exception e) {
                            return Either.left("Failed to rename function: " + e.getMessage());
                        }
                    })
                    .orElse(Either.left("No function at address: " + addressStr));
            } finally {
                program.endTransaction(tx, true);
            }
        }).orElse(Either.left("No program loaded"));
    }

    public Either<String, List<String>> listSegments(int offset, int limit) {
        return context.<Either<String, List<String>>>withProgram(program -> 
            Either.<String, List<String>>right(
                Arrays.stream(program.getMemory().getBlocks())
                    .map(block -> String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()))
                    .skip(offset)
                    .limit(limit)
                    .collect(Collectors.toList())
            )
        ).orElse(Either.left("No program loaded"));
    }

    public Either<String, List<String>> listImports(int offset, int limit) {
        return context.<Either<String, List<String>>>withProgram(program -> 
            Either.<String, List<String>>right(
                StreamSupport.stream(program.getSymbolTable().getExternalSymbols().spliterator(), false)
                    .map(symbol -> symbol.getName() + " -> " + symbol.getAddress())
                    .skip(offset)
                    .limit(limit)
                    .collect(Collectors.toList())
            )
        ).orElse(Either.left("No program loaded"));
    }

    public Either<String, List<String>> listExports(int offset, int limit) {
        return context.<Either<String, List<String>>>withProgram(program -> 
            Either.<String, List<String>>right(
                StreamSupport.stream(program.getSymbolTable().getAllSymbols(true).spliterator(), false)
                    .filter(Symbol::isExternalEntryPoint)
                    .map(symbol -> symbol.getName() + " -> " + symbol.getAddress())
                    .skip(offset)
                    .limit(limit)
                    .collect(Collectors.toList())
            )
        ).orElse(Either.left("No program loaded"));
    }

    public Either<String, List<String>> listNamespaces(int offset, int limit) {
        return context.<Either<String, List<String>>>withProgram(program -> {
            Set<String> namespaces = new HashSet<>();
            for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
                Namespace ns = symbol.getParentNamespace();
                if (ns != null && !(ns instanceof GlobalNamespace)) {
                    namespaces.add(ns.getName());
                }
            }
            return Either.<String, List<String>>right(
                new ArrayList<>(namespaces).stream()
                    .sorted()
                    .skip(offset)
                    .limit(limit)
                    .collect(Collectors.toList())
            );
        }).orElse(Either.left("No program loaded"));
    }

    public Either<String, List<String>> searchFunctionsByName(String searchTerm, int offset, int limit) {
        return context.<Either<String, List<String>>>withProgram(program -> 
            Either.<String, List<String>>right(
                streamFunctions(program)
                    .filter(func -> func.getName().toLowerCase().contains(searchTerm.toLowerCase()))
                    .map(Function::getName)
                    .skip(offset)
                    .limit(limit)
                    .collect(Collectors.toList())
            )
        ).orElse(Either.left("No program loaded"));
    }

    public Either<String, List<String>> listFunctions(int offset, int limit) {
        return context.<Either<String, List<String>>>withProgram(program -> 
            Either.<String, List<String>>right(
                streamFunctions(program)
                    .map(func -> String.format("%s @ %s", func.getName(), func.getEntryPoint()))
                    .skip(offset)
                    .limit(limit)
                    .collect(Collectors.toList())
            )
        ).orElse(Either.left("No program loaded"));
    }

    public String getFunctionByAddress(String addressStr) {
        return context.<String>withProgram(program -> 
            parseAddress(program, addressStr)
                .flatMap(addr -> findFunctionByAddress(program, addr))
                .map(func -> String.format("Function: %s @ %s", func.getName(), func.getEntryPoint()))
                .fold(err -> "No function found at address: " + err, output -> output)
        ).orElse("No program loaded");
    }

    public String disassembleFunction(String addressStr) {
        return context.<String>withProgram(program -> 
            parseAddress(program, addressStr)
                .flatMap(addr -> findFunctionByAddress(program, addr))
                .map(func -> disassembleFunctionInstructions(program, func))
                .fold(err -> "Function not found at address: " + err, output -> output)
        ).orElse("No program loaded");
    }

    // Data Operations
    // ===============

    public Either<String, List<String>> listDefinedData(int offset, int limit) {
        return context.<Either<String, List<String>>>withProgram(program -> {
            try {
                List<String> lines = new ArrayList<>();
                for (MemoryBlock block : program.getMemory().getBlocks()) {
                    DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
                    while (it.hasNext()) {
                        Data data = it.next();
                        if (block.contains(data.getAddress())) {
                            String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                            DataType dataType = data.getDataType();
                            String typeName = "(unknown)";
                            if (dataType != null) {
                                String displayName = dataType.getDisplayName();
                                if (displayName != null && !displayName.trim().isEmpty()) {
                                    typeName = displayName;
                                } else {
                                    String fallbackName = dataType.getName();
                                    if (fallbackName != null && !fallbackName.trim().isEmpty()) {
                                        typeName = fallbackName;
                                    }
                                }
                            }
                            String valRepr = data.getDefaultValueRepresentation();
                            lines.add(String.format("%s: %s (%s) = %s",
                                data.getAddress(),
                                escapeNonAscii(label),
                                escapeNonAscii(typeName),
                                escapeNonAscii(valRepr)));
                        }
                    }
                }
                return Either.right(lines.stream().skip(offset).limit(limit).collect(Collectors.toList()));
            } catch (Exception e) {
                return Either.left("Error listing defined data: " + e.getMessage());
            }
        }).orElse(Either.left("No program loaded"));
    }

    public Either<String, String> createOrUpdateDataItem(String addressStr, String dataTypeName, String newName) {
        String normalizedTypeName = dataTypeName != null ? dataTypeName.trim() : "";
        String normalizedNewName = newName != null ? newName.trim() : "";
        boolean hasType = !normalizedTypeName.isEmpty();
        boolean hasName = !normalizedNewName.isEmpty();

        if (!hasType && !hasName) {
            return Either.left("At least one of data_type or new_name is required");
        }

        return context.<Either<String, String>>withProgram(program -> {
            int tx = program.startTransaction("Create or update data item");
            boolean success = false;
            try {
                Either<String, String> result = parseAddress(program, addressStr)
                    .flatMap(addr -> {
                        Data existingData = program.getListing().getDefinedDataAt(addr);
                        if (!hasType && existingData == null) {
                            return Either.left("No data at address: " + addr + " (data_type required to create)");
                        }

                        List<String> changes = new ArrayList<>();

                        if (hasType) {
                            Either<String, DataType> dataTypeResult = resolveDataType(program.getDataTypeManager(), normalizedTypeName);
                            if (dataTypeResult.isLeft()) {
                                return Either.left(dataTypeResult.getLeft());
                            }

                            DataType resolvedType = dataTypeResult.get();
                            int length = resolvedType.getLength();
                            if (length <= 0) {
                                return Either.left("Data type '" + resolvedType.getName() + "' has unsupported length: " + length);
                            }

                            Address endAddr;
                            try {
                                endAddr = addr.addNoWrap(length - 1L);
                            } catch (AddressOverflowException e) {
                                return Either.left("Data range overflows address space: " + e.getMessage());
                            }

                            try {
                                program.getListing().clearCodeUnits(addr, endAddr, false);
                                Data createdData = program.getListing().createData(addr, resolvedType);
                                if (createdData == null) {
                                    return Either.left("Failed to create data at address: " + addr);
                                }
                            } catch (Exception e) {
                                return Either.left("Error creating/updating data at " + addr + ": " + e.getMessage());
                            }

                            String typeDisplayName = resolvedType.getDisplayName() != null
                                ? resolvedType.getDisplayName()
                                : resolvedType.getName();
                            if (existingData == null) {
                                changes.add("created data type '" + typeDisplayName + "'");
                            } else {
                                changes.add("updated data type to '" + typeDisplayName + "'");
                            }
                        }

                        if (hasName) {
                            try {
                                SymbolTable symTable = program.getSymbolTable();
                                Symbol symbol = symTable.getPrimarySymbol(addr);
                                if (symbol != null) {
                                    symbol.setName(normalizedNewName, SourceType.USER_DEFINED);
                                } else {
                                    symTable.createLabel(addr, normalizedNewName, SourceType.USER_DEFINED);
                                }
                                changes.add("set label to '" + normalizedNewName + "'");
                            } catch (Exception e) {
                                return Either.left("Error renaming data label at " + addr + ": " + e.getMessage());
                            }
                        }

                        return Either.right("Successfully " + String.join(" and ", changes) + " at " + addr);
                    })
                    .orElse(Either.left("Invalid address: " + addressStr));

                success = result.isRight();
                return result;
            } finally {
                program.endTransaction(tx, success);
            }
        }).orElse(Either.left("No program loaded"));
    }

    // Current Location Operations (GUI-specific)
    // ==========================================

    public String getCurrentAddress() {
        return context.getCurrentAddress()
            .map(Address::toString)
            .orElse(context.isGuiMode() ? "No current location" : "Not available in headless mode");
    }

    public String getCurrentFunction() {
        return context.getCurrentFunction()
            .orElse(context.isGuiMode() ? "No function at current location" : "Not available in headless mode");
    }

    public String goToTarget(String target) {
        try {
            if (target == null || target.trim().isEmpty()) {
                return "Error: target is required";
            }
            if (!context.isGuiMode()) {
                return "Not available in headless mode";
            }

            String normalizedTarget = target.trim();
            return context.<String>withProgram(program -> {
                Optional<PluginTool> toolOpt = context.getTool();
                if (toolOpt.isEmpty()) {
                    return "Error: GoTo service unavailable";
                }

                GoToService goToService = toolOpt.get().getService(GoToService.class);
                if (goToService == null) {
                    return "Error: GoTo service unavailable";
                }

                Either<String, Address> parsedAddress = parseAddress(program, normalizedTarget);
                if (parsedAddress.isRight()) {
                    Address address = parsedAddress.get();
                    boolean ok = goToService.goTo(address, program);
                    if (!ok) {
                        return "Error: navigation failed for target: " + normalizedTarget;
                    }
                    return "Navigated to address: " + address;
                }

                Either<String, Function> functionResult = findFunctionByName(program, normalizedTarget);
                if (functionResult.isLeft()) {
                    return "Function not found: " + normalizedTarget;
                }

                Function function = functionResult.get();
                Address functionAddress = function.getEntryPoint();
                boolean ok = goToService.goTo(functionAddress, program);
                if (!ok) {
                    return "Error: navigation failed for target: " + normalizedTarget;
                }
                return String.format("Navigated to function: %s @ %s", function.getName(), functionAddress);
            }).orElse("No program loaded");
        } catch (Exception e) {
            return "Error: goto failed: " + e.getMessage();
        }
    }

    // Cross-Reference Operations
    // =========================

    public Either<String, List<String>> getXrefsTo(String addressStr, int offset, int limit) {
        return context.<Either<String, List<String>>>withProgram(program -> 
            parseAddress(program, addressStr)
                .flatMap(addr -> {
                    List<String> refs = new ArrayList<>();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(addr);

                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();

                        Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        String label = getPrimarySymbolLabel(program, fromAddr).fold(err -> "", value -> value);
                        String labelInfo = label.isEmpty() ? "" : " [label:" + label + "]";

                        refs.add(String.format("From %s%s%s [%s]", fromAddr, funcInfo, labelInfo, refType.getName()));
                    }

                    return Either.right(refs.stream().skip(offset).limit(limit).collect(Collectors.toList()));
                })
                .orElse(Either.left("Invalid address: " + addressStr))
        ).orElse(Either.left("No program loaded"));
    }

    public Either<String, List<String>> getXrefsFrom(String addressStr, int offset, int limit) {
        return context.<Either<String, List<String>>>withProgram(program -> 
            parseAddress(program, addressStr)
                .flatMap(addr -> {
                    List<String> refs = new ArrayList<>();
                    Reference[] refsFrom = program.getReferenceManager().getReferencesFrom(addr);

                    for (Reference ref : refsFrom) {
                        Address toAddr = ref.getToAddress();
                        RefType refType = ref.getReferenceType();

                        Function toFunc = program.getFunctionManager().getFunctionContaining(toAddr);
                        String funcInfo = (toFunc != null) ? " in " + toFunc.getName() : "";
                        String label = getPrimarySymbolLabel(program, toAddr).fold(err -> "", value -> value);
                        String labelInfo = label.isEmpty() ? "" : " [label:" + label + "]";

                        refs.add(String.format("To %s%s%s [%s]", toAddr, funcInfo, labelInfo, refType.getName()));
                    }

                    return Either.right(refs.stream().skip(offset).limit(limit).collect(Collectors.toList()));
                })
                .orElse(Either.left("Invalid address: " + addressStr))
        ).orElse(Either.left("No program loaded"));
    }

    public Either<String, List<String>> getFunctionXrefs(String functionName, int offset, int limit) {
        return context.<Either<String, List<String>>>withProgram(program -> 
            findFunctionByName(program, functionName)
                .map(func -> {
                    List<String> refs = new ArrayList<>();
                    AddressSetView body = func.getBody();
                    
                    for (AddressRange range : body.getAddressRanges()) {
                        Address addr = range.getMinAddress();
                        while (addr != null && range.contains(addr)) {
                            Reference[] refsFrom = program.getReferenceManager().getReferencesFrom(addr);
                            for (Reference ref : refsFrom) {
                                if (ref.getReferenceType().isCall()) {
                                    Address toAddr = ref.getToAddress();
                                    Function toFunc = program.getFunctionManager().getFunctionContaining(toAddr);
                                    String target = (toFunc != null) ? toFunc.getName() : toAddr.toString();
                                    refs.add(String.format("%s calls %s", addr, target));
                                }
                            }
                            addr = addr.next();
                        }
                    }
                    
                    return refs.stream().skip(offset).limit(limit).collect(Collectors.toList());
                })
        ).orElse(Either.left("No program loaded"));
    }

    // String Analysis
    // ==============

    public Either<String, List<String>> getStrings(int offset, int limit) {
        return getStrings(offset, limit, null);
    }

    public Either<String, List<String>> getStrings(int offset, int limit, String filter) {
        return context.<Either<String, List<String>>>withProgram(program -> {
            try {
                List<String> strings = new ArrayList<>();

                for (MemoryBlock block : program.getMemory().getBlocks()) {
                    if (block.isInitialized()) {
                        DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
                        while (it.hasNext()) {
                            Data data = it.next();
                            if (data.hasStringValue()) {
                                String value = data.getDefaultValueRepresentation();
                                String stringEntry = String.format("%s: %s", data.getAddress(), escapeNonAscii(value));

                                // Apply filter if specified
                                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                                    strings.add(stringEntry);
                                }
                            }
                        }
                    }
                }

                return Either.right(strings.stream().skip(offset).limit(limit).collect(Collectors.toList()));
            } catch (Exception e) {
                return Either.left("Error listing strings: " + e.getMessage());
            }
        }).orElse(Either.left("No program loaded"));
    }

    // Comment Operations
    // =================

    public boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    public boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        return context.<Boolean>withProgram(program -> {
            int tx = program.startTransaction(transactionName);
            try {
                return parseAddress(program, addressStr)
                    .map(addr -> {
                        try {
                            CodeUnit cu = program.getListing().getCodeUnitAt(addr);
                            if (cu != null) {
                                cu.setComment(commentType, comment);
                            } else {
                                context.showError("No code unit found at address " + addr);
                                return false;
                            }
                            return true;
                        } catch (Exception e) {
                            context.showError("Error setting comment: " + e.getMessage());
                            return false;
                        }
                    })
                    .fold(err -> { context.showError(err); return false; }, r -> r);
            } finally {
                program.endTransaction(tx, true);
            }
        }).orElse(false);
    }

    // Variable Operations
    // ==================

    public String renameVariableInFunction(String functionName, String oldName, String newName) {
        return context.<String>withProgram(program -> 
            findFunctionByName(program, functionName)
                .flatMap(func -> {
                    DecompInterface decomp = new DecompInterface();
                    decomp.openProgram(program);
                    DecompileResults results = decomp.decompileFunction(func, 30, context.getTaskMonitor());

                    if (results == null || !results.decompileCompleted()) {
                        return Either.left("Decompilation failed for function " + functionName);
                    }

                    ghidra.program.model.pcode.HighFunction hf = results.getHighFunction();
                    if (hf == null || hf.getLocalSymbolMap() == null) {
                        return Either.left("No local symbol map available for function " + functionName);
                    }

                    ghidra.program.model.pcode.LocalSymbolMap localSymbolMap = hf.getLocalSymbolMap();

                    boolean newNameExists = StreamSupport.stream(
                        java.util.Spliterators.spliteratorUnknownSize(localSymbolMap.getSymbols(), java.util.Spliterator.ORDERED), false)
                        .anyMatch(symbol -> symbol.getName().equals(newName));

                    if (newNameExists) {
                        return Either.left("Error: A variable with name '" + newName + "' already exists in this function");
                    }

                    return StreamSupport.stream(
                        java.util.Spliterators.spliteratorUnknownSize(localSymbolMap.getSymbols(), java.util.Spliterator.ORDERED), false)
                        .filter(symbol -> symbol.getName().equals(oldName))
                        .findFirst()
                        .map(highSymbol -> {
                            int tx = program.startTransaction("Rename variable");
                            try {
                                boolean commitRequired = checkFullCommit(highSymbol, hf);

                                if (commitRequired) {
                                    ghidra.program.model.pcode.HighFunctionDBUtil.commitParamsToDatabase(
                                        hf, false,
                                        ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT,
                                        func.getSignatureSource());
                                }

                                ghidra.program.model.pcode.HighFunctionDBUtil.updateDBVariable(
                                    highSymbol,
                                    newName,
                                    null,  // Keep existing data type
                                    SourceType.USER_DEFINED
                                );

                                return Either.<String, String>right("Variable renamed successfully");
                            } catch (Exception e) {
                                return Either.<String, String>left("Failed to rename variable: " + e.getMessage());
                            } finally {
                                program.endTransaction(tx, true);
                            }
                        })
                        .orElse(Either.left("Variable '" + oldName + "' not found in function '" + functionName + "'"));
                })
                .fold(err -> "Function '" + functionName + "' not found: " + err, s -> s)
        ).orElse("No program loaded");
    }
    
    // Helper method from the example code for checking if full commit is needed
    private boolean checkFullCommit(ghidra.program.model.pcode.HighSymbol highSymbol, ghidra.program.model.pcode.HighFunction hfunction) {
        if (highSymbol != null && !highSymbol.isParameter()) {
            return false;
        }
        Function function = hfunction.getFunction();
        Parameter[] parameters = function.getParameters();
        ghidra.program.model.pcode.LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
        int numParams = localSymbolMap.getNumParams();
        if (numParams != parameters.length) {
            return true;
        }
        for (int i = 0; i < numParams; i++) {
            ghidra.program.model.pcode.HighSymbol param = localSymbolMap.getParamSymbol(i);
            if (param.getCategoryIndex() != i) {
                return true;
            }
            ghidra.program.model.listing.VariableStorage storage = param.getStorage();
            if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
                return true;
            }
        }
        return false;
    }

    public String setLocalVariableType(String functionAddress, String variableName, String newType) {
        return context.<String>withProgram(program -> {
            int tx = program.startTransaction("Set variable type");
            try {
                return parseAddress(program, functionAddress)
                    .flatMap(addr -> findFunctionByAddress(program, addr))
                    .flatMap(func -> {
                        // Decompile function to get high function
                        DecompInterface decomp = new DecompInterface();
                        decomp.openProgram(program);
                        DecompileResults results = decomp.decompileFunction(func, 30, context.getTaskMonitor());

                        if (results == null || !results.decompileCompleted()) {
                            return Either.left("Decompilation failed for function at " + functionAddress);
                        }

                        ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
                        if (highFunction == null) {
                            return Either.left("No high function available for " + functionAddress);
                        }

                        DataTypeManager dtm = program.getDataTypeManager();

                        return findSymbolByName(highFunction, variableName)
                            .flatMap(symbol -> resolveDataType(dtm, newType)
                                .flatMap(dataType -> {
                                    try {
                                        ghidra.program.model.pcode.HighFunctionDBUtil.updateDBVariable(
                                            symbol,
                                            symbol.getName(),
                                            dataType,
                                            SourceType.USER_DEFINED
                                        );
                                        return Either.<String, String>right("Variable type set successfully to " + dataType.getName());
                                    } catch (Exception e) {
                                        return Either.<String, String>left("Failed to update variable: " + e.getMessage());
                                    }
                                })
                            );
                    })
                    .fold(err -> "No function at address: " + err, s -> s);

            } catch (Exception e) {
                return "Error setting variable type: " + e.getMessage();
            } finally {
                program.endTransaction(tx, true);
            }
        }).orElse("No program loaded");
    }
    
    private Either<String, ghidra.program.model.pcode.HighSymbol> findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        java.util.Iterator<ghidra.program.model.pcode.HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        return StreamSupport.stream(
            java.util.Spliterators.spliteratorUnknownSize(symbols, java.util.Spliterator.ORDERED), false)
            .filter(symbol -> symbol.getName().equals(variableName))
            .findFirst()
            .map(Either::<String, ghidra.program.model.pcode.HighSymbol>right)
            .orElse(Either.left("Variable '" + variableName + "' not found"));
    }
    
    private Either<String, DataType> resolveDataType(DataTypeManager dtm, String typeName) {
        try {
            // Use Ghidra's built-in C parser - handles pointers, built-ins, and complex types
            ghidra.app.util.cparser.C.CParser parser = new ghidra.app.util.cparser.C.CParser(dtm);
            DataType parsedType = parser.parse(typeName);
            if (parsedType != null) {
                return Either.right(parsedType);
            }
        } catch (Exception e) {
            // fall through to fallback logic below
        }

        // Fallback using functional approach
        DataType direct = dtm.getDataType("/" + typeName);
        if (direct != null) {
            return Either.right(direct);
        }

        return StreamSupport.stream(
            java.util.Spliterators.spliteratorUnknownSize(dtm.getAllDataTypes(), java.util.Spliterator.ORDERED), false)
            .filter(dt -> dt.getName().equalsIgnoreCase(typeName))
            .findFirst()
            .map(Either::<String, DataType>right)
            .orElse(Either.left("Could not resolve data type: " + typeName));
    }

    // Function Prototype Operations
    // ============================

    public String setFunctionPrototype(String functionAddress, String prototype) {
        return context.<String>withProgram(program ->
            parseAddress(program, functionAddress)
                .flatMap(addr -> findFunctionByAddress(program, addr))
                .map(func -> {
                    int tx = program.startTransaction("Set function prototype");
                    boolean success = false;
                    try {
                        // Get data type manager
                        DataTypeManager dtm = program.getDataTypeManager();
                        
                        // Create function signature parser
                        // Don't pass dtms or else headed mode will open dialog boxes!
                        FunctionSignatureParser parser = new FunctionSignatureParser(dtm, null);
                        
                        // Parse the prototype
                        FunctionDefinitionDataType sig = parser.parse(null, prototype);
                        if (sig == null) {
                            return "Failed to parse function prototype: " + prototype;
                        }
                        
                        // Create and apply the command
                        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                            func.getEntryPoint(), sig, SourceType.USER_DEFINED);
                        
                        // Apply the command
                        success = cmd.applyTo(program, context.getTaskMonitor());
                        
                        if (success) {
                            return "Function prototype updated successfully";
                        } else {
                            return "Failed to apply function signature: " + cmd.getStatusMsg();
                        }
                    } catch (Exception e) {
                        return "Error setting function prototype: " + e.getMessage();
                    } finally {
                        program.endTransaction(tx, success);
                    }
                })
                .fold(err -> "Function not found at address: " + err, s -> s)
        ).orElse("No program loaded");
    }

    // Type Creation and Data Export
    // =============================

    public String createTypeFromCDefinition(String cDefinition) {
        return context.<String>withProgram(program -> {
            int tx = program.startTransaction("Create type from C definition");
            try {
                DataTypeManager dtm = program.getDataTypeManager();
                
                // Parse C definition using Ghidra's C parser
                ghidra.app.util.cparser.C.CParser parser = new ghidra.app.util.cparser.C.CParser(dtm);
                
                // Parse the definition
                DataType parsedType = parser.parse(cDefinition);
                
                if (parsedType == null) {
                    return "Failed to parse C definition: " + cDefinition;
                }
                
                dtm.addDataType(parsedType, null);
                
                return "Successfully created type: " + parsedType.getName() + " (" + parsedType.getClass().getSimpleName() + ")";
                
            } catch (ghidra.app.util.cparser.C.ParseException e) {
                return "Parse error in C definition: " + e.getMessage();
            } catch (Exception e) {
                return "Error creating type from C definition: " + e.getMessage();
            } finally {
                program.endTransaction(tx, true);
            }
        }).orElse("No program loaded");
    }

    public String exportFunctions() {
        return context.<String>withProgram(program -> {
            StringBuilder export = new StringBuilder();
            export.append("Functions Export:\n");
            
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            for (Function func : functions) {
                export.append(String.format("Function: %s @ %s\n", 
                    func.getName(), func.getEntryPoint()));
                export.append(String.format("  Signature: %s\n", func.getSignature()));
                export.append(String.format("  Parameters: %d\n", func.getParameterCount()));
                export.append("\n");
            }
            
            return export.toString();
        }).orElse("No program loaded");
    }

    public String exportData(String addressStr, int length) {
        return context.<String>withProgram(program -> {
            return parseAddress(program, addressStr)
                .fold(err -> "Error: " + err,
                    addr -> {
                        try {
                            if (length <= 0 || length > 1024 * 1024) { // Limit to 1MB for safety
                                return "Error: Invalid length (must be 1-1048576): " + length;
                            }

                            byte[] bytes = new byte[length];
                            int bytesRead = program.getMemory().getBytes(addr, bytes);

                            if (bytesRead != length) {
                                return "Error: Could only read " + bytesRead + " of " + length + " bytes";
                            }

                            // Convert to hex string using functional approach
                            return java.util.stream.IntStream.range(0, bytes.length)
                                .mapToObj(i -> String.format("%02x", bytes[i] & 0xFF))
                                .collect(Collectors.joining());
                        } catch (Exception e) {
                            return "Error: " + e.getMessage();
                        }
                    }
                );
        }).orElse("Error: No program loaded");
    }

    // Helper Methods (Pure Functions)
    // ==============================

    private Stream<Function> streamFunctions(Program program) {
        return StreamSupport.stream(
            program.getFunctionManager().getFunctions(true).spliterator(), false);
    }

    private Either<String, Function> findFunctionByName(Program program, String name) {
        return streamFunctions(program)
            .filter(func -> func.getName().equals(name))
            .findFirst()
            .map(Either::<String, Function>right)
            .orElse(Either.left("Function '" + name + "' not found"));
    }

    private Either<String, Function> findFunctionByAddress(Program program, Address address) {
        Function func = program.getFunctionManager().getFunctionAt(address);
        return func != null ? Either.right(func) : Either.left("No function at address: " + address);
    }

    private Either<String, Address> parseAddress(Program program, String addressStr) {
        try {
            if (addressStr == null || addressStr.trim().isEmpty()) {
                return Either.left("Invalid address format: " + addressStr);
            }
            Address parsed = program.getAddressFactory().getAddress(addressStr.trim());
            if (parsed == null) {
                return Either.left("Invalid address format: " + addressStr);
            }
            return Either.right(parsed);
        } catch (Exception e) {
            return Either.left("Invalid address format: " + addressStr + " - " + e.getMessage());
        }
    }

    private Either<String, String> decompileFunction(Program program, Function function) {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        
        DecompileResults results = decomp.decompileFunction(function, 30, context.getTaskMonitor());
        if (results == null) {
            return Either.left("Decompilation returned null");
        }
        if (!results.decompileCompleted()) {
            return Either.left("Decompilation failed");
        }
        try {
            return Either.right(results.getDecompiledFunction().getC());
        } catch (Exception e) {
            return Either.left("Error extracting decompiled C: " + e.getMessage());
        }
    }

    private boolean tryRename(Function function, String newName) {
        try {
            function.setName(newName, SourceType.USER_DEFINED);
            return true;
        } catch (Exception e) {
            context.showError("Failed to rename function: " + e.getMessage());
            return false;
        }
    }

    private String disassembleFunctionInstructions(Program program, Function function) {
        try {
            InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
            
            String header = String.format("Function: %s @ %s\n", function.getName(), function.getEntryPoint());
            String instructionList = StreamSupport.stream(
                java.util.Spliterators.spliteratorUnknownSize(instructions, java.util.Spliterator.ORDERED), false)
                .map(inst -> String.format("%s: %s", inst.getAddress(), inst.toString()))
                .collect(Collectors.joining("\n"));
                
            return header + instructionList;
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }

    private Either<String, String> getPrimarySymbolLabel(Program program, Address address) {
        try {
            Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
            if (symbol == null) {
                return Either.right("");
            }
            String symbolName = symbol.getName();
            if (symbolName == null || symbolName.trim().isEmpty()) {
                return Either.right("");
            }
            return Either.right(escapeNonAscii(symbolName));
        } catch (Exception e) {
            return Either.left("Error resolving primary symbol label at " + address + ": " + e.getMessage());
        }
    }

    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c <= 126) {
                result.append(c);
            } else {
                result.append(String.format("\\x%02x", (int) c));
            }
        }
        return result.toString();
    }
}
