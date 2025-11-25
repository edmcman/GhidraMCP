package com.lauriewired;

import com.lauriewired.context.GhidraContext;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.data.*;
import ghidra.app.decompiler.*;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.*;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import generic.jar.ResourceFile;
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
            .map(script -> executeScript(script, scriptName))
            .orElse("Script execution failed");
    }

    private Optional<ResourceFile> createScriptFile(String scriptName, String scriptSource) {
        try {
            ResourceFile scriptDir = GhidraScriptUtil.getUserScriptDirectory();
            File scriptFile = new File(scriptDir.getFile(false), scriptName);
            try (FileWriter writer = new FileWriter(scriptFile)) {
                writer.write(scriptSource);
            }
            return Optional.of(new ResourceFile(scriptFile));
        } catch (IOException e) {
            Msg.error(this, "Error writing script file: " + e.getMessage());
            return Optional.empty();
        }
    }

    private Optional<GhidraScript> loadScript(ResourceFile scriptFile) {
        return java.util.stream.IntStream.range(0, 3)
            .mapToObj(attempt -> {
                try {
                    if (attempt > 0) {
                        Thread.sleep(1000);
                    }
                    GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
                    return provider.getScriptInstance(scriptFile, new PrintWriter(System.err));
                } catch (Exception e) {
                    Msg.error(this, "Script load attempt " + (attempt + 1) + " failed");
                }
                return null;
            })
            .filter(Objects::nonNull)
            .findFirst();
    }

    private String executeScript(GhidraScript script, String scriptName) {
        try {
            StringWriter stringWriter = new StringWriter();
            PrintWriter outWriter = new PrintWriter(stringWriter);
            script.execute(getState(), TaskMonitor.DUMMY, outWriter);
            return stringWriter.toString();
        } catch (Exception e) {
            return "Error running script: " + e.getMessage();
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

    public List<String> getAllFunctionNames(int offset, int limit) {
        return context.<List<String>>withProgram(program -> 
            streamFunctions(program)
                .map(Function::getName)
                .skip(offset)
                .limit(limit)
                .collect(Collectors.toList())
        ).orElse(Collections.singletonList("No program loaded"));
    }

    public List<String> getAllClassNames(int offset, int limit) {
        return context.<List<String>>withProgram(program -> {
            Set<String> classNames = new HashSet<>();
            for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
                Namespace ns = symbol.getParentNamespace();
                if (ns != null && !ns.isGlobal()) {
                    classNames.add(ns.getName());
                }
            }
            return new ArrayList<>(classNames).stream()
                .sorted()
                .skip(offset)
                .limit(limit)
                .collect(Collectors.toList());
        }).orElse(Collections.singletonList("No program loaded"));
    }

    public String decompileFunctionByName(String name) {
        return context.<String>withProgram(program -> 
            findFunctionByName(program, name)
                .map(func -> decompileFunction(program, func))
                .orElse("Function not found")
        ).orElse("No program loaded");
    }

    public String decompileFunctionByAddress(String addressStr) {
        return context.<String>withProgram(program -> 
            parseAddress(program, addressStr)
                .flatMap(addr -> findFunctionByAddress(program, addr))
                .map(func -> decompileFunction(program, func))
                .orElse("Function not found at address")
        ).orElse("No program loaded");
    }

    public boolean renameFunction(String oldName, String newName) {
        return context.<Boolean>withProgram(program -> {
            int tx = program.startTransaction("Rename function");
            try {
                return findFunctionByName(program, oldName)
                    .map(func -> tryRename(func, newName))
                    .orElse(false);
            } finally {
                program.endTransaction(tx, true);
            }
        }).orElse(false);
    }

    public boolean renameFunctionByAddress(String addressStr, String newName) {
        return context.<Boolean>withProgram(program -> {
            int tx = program.startTransaction("Rename function by address");
            try {
                return parseAddress(program, addressStr)
                    .flatMap(addr -> findFunctionByAddress(program, addr))
                    .map(func -> tryRename(func, newName))
                    .orElse(false);
            } finally {
                program.endTransaction(tx, true);
            }
        }).orElse(false);
    }

    public List<String> listSegments(int offset, int limit) {
        return context.<List<String>>withProgram(program -> 
            Arrays.stream(program.getMemory().getBlocks())
                .map(block -> String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()))
                .skip(offset)
                .limit(limit)
                .collect(Collectors.toList())
        ).orElse(Collections.singletonList("No program loaded"));
    }

    public List<String> listImports(int offset, int limit) {
        return context.<List<String>>withProgram(program -> 
            StreamSupport.stream(program.getSymbolTable().getExternalSymbols().spliterator(), false)
                .map(symbol -> symbol.getName() + " -> " + symbol.getAddress())
                .skip(offset)
                .limit(limit)
                .collect(Collectors.toList())
        ).orElse(Collections.singletonList("No program loaded"));
    }

    public List<String> listExports(int offset, int limit) {
        return context.<List<String>>withProgram(program -> 
            StreamSupport.stream(program.getSymbolTable().getAllSymbols(true).spliterator(), false)
                .filter(Symbol::isExternalEntryPoint)
                .map(symbol -> symbol.getName() + " -> " + symbol.getAddress())
                .skip(offset)
                .limit(limit)
                .collect(Collectors.toList())
        ).orElse(Collections.singletonList("No program loaded"));
    }

    public List<String> listNamespaces(int offset, int limit) {
        return context.<List<String>>withProgram(program -> {
            Set<String> namespaces = new HashSet<>();
            for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
                Namespace ns = symbol.getParentNamespace();
                if (ns != null && !(ns instanceof GlobalNamespace)) {
                    namespaces.add(ns.getName());
                }
            }
            return new ArrayList<>(namespaces).stream()
                .sorted()
                .skip(offset)
                .limit(limit)
                .collect(Collectors.toList());
        }).orElse(Collections.singletonList("No program loaded"));
    }

    public List<String> searchFunctionsByName(String searchTerm, int offset, int limit) {
        return context.<List<String>>withProgram(program -> 
            streamFunctions(program)
                .filter(func -> func.getName().toLowerCase().contains(searchTerm.toLowerCase()))
                .map(Function::getName)
                .skip(offset)
                .limit(limit)
                .collect(Collectors.toList())
        ).orElse(Collections.singletonList("No program loaded"));
    }

    public List<String> listFunctions(int offset, int limit) {
        return context.<List<String>>withProgram(program -> 
            streamFunctions(program)
                .map(func -> String.format("%s @ %s", func.getName(), func.getEntryPoint()))
                .skip(offset)
                .limit(limit)
                .collect(Collectors.toList())
        ).orElse(Collections.singletonList("No program loaded"));
    }

    public String getFunctionByAddress(String addressStr) {
        return context.<String>withProgram(program -> 
            parseAddress(program, addressStr)
                .flatMap(addr -> findFunctionByAddress(program, addr))
                .map(func -> String.format("Function: %s @ %s", func.getName(), func.getEntryPoint()))
                .orElse("No function found at address")
        ).orElse("No program loaded");
    }

    public String disassembleFunction(String addressStr) {
        return context.<String>withProgram(program -> 
            parseAddress(program, addressStr)
                .flatMap(addr -> findFunctionByAddress(program, addr))
                .map(func -> disassembleFunctionInstructions(program, func))
                .orElse("Function not found at address")
        ).orElse("No program loaded");
    }

    // Data Operations
    // ===============

    public List<String> listDefinedData(int offset, int limit) {
        return context.<List<String>>withProgram(program -> {
            List<String> lines = new ArrayList<>();
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
                while (it.hasNext()) {
                    Data data = it.next();
                    if (block.contains(data.getAddress())) {
                        String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                        String valRepr = data.getDefaultValueRepresentation();
                        lines.add(String.format("%s: %s = %s",
                            data.getAddress(), escapeNonAscii(label), escapeNonAscii(valRepr)));
                    }
                }
            }
            return lines.stream().skip(offset).limit(limit).collect(Collectors.toList());
        }).orElse(Collections.singletonList("No program loaded"));
    }

    public boolean renameDataAtAddress(String addressStr, String newName) {
        return context.<Boolean>withProgram(program -> {
            int tx = program.startTransaction("Rename data");
            try {
                return parseAddress(program, addressStr)
                    .map(addr -> {
                        Data data = program.getListing().getDefinedDataAt(addr);
                        if (data != null) {
                            SymbolTable symTable = program.getSymbolTable();
                            Symbol symbol = symTable.getPrimarySymbol(addr);
                            try {
                                if (symbol != null) {
                                    symbol.setName(newName, SourceType.USER_DEFINED);
                                } else {
                                    symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                                }
                                return true;
                            } catch (Exception e) {
                                context.showError("Error renaming data: " + e.getMessage());
                                return false;
                            }
                        }
                        return false;
                    })
                    .orElse(false);
            } finally {
                program.endTransaction(tx, true);
            }
        }).orElse(false);
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

    // Cross-Reference Operations
    // =========================

    public List<String> getXrefsTo(String addressStr, int offset, int limit) {
        return context.<List<String>>withProgram(program -> 
            parseAddress(program, addressStr)
                .map(addr -> {
                    List<String> refs = new ArrayList<>();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(addr);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                    
                    return refs.stream().skip(offset).limit(limit).collect(Collectors.toList());
                })
                .orElse(Collections.singletonList("Invalid address: " + addressStr))
        ).orElse(Collections.singletonList("No program loaded"));
    }

    public List<String> getXrefsFrom(String addressStr, int offset, int limit) {
        return context.<List<String>>withProgram(program -> 
            parseAddress(program, addressStr)
                .map(addr -> {
                    List<String> refs = new ArrayList<>();
                    Reference[] refsFrom = program.getReferenceManager().getReferencesFrom(addr);
                    
                    for (Reference ref : refsFrom) {
                        Address toAddr = ref.getToAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function toFunc = program.getFunctionManager().getFunctionContaining(toAddr);
                        String funcInfo = (toFunc != null) ? " in " + toFunc.getName() : "";
                        
                        refs.add(String.format("To %s%s [%s]", toAddr, funcInfo, refType.getName()));
                    }
                    
                    return refs.stream().skip(offset).limit(limit).collect(Collectors.toList());
                })
                .orElse(Collections.singletonList("Invalid address: " + addressStr))
        ).orElse(Collections.singletonList("No program loaded"));
    }

    public List<String> getFunctionXrefs(String functionName, int offset, int limit) {
        return context.<List<String>>withProgram(program -> 
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
                .orElse(Collections.singletonList("Function not found: " + functionName))
        ).orElse(Collections.singletonList("No program loaded"));
    }

    // String Analysis
    // ==============

    public List<String> getStrings(int offset, int limit) {
        return getStrings(offset, limit, null);
    }

    public List<String> getStrings(int offset, int limit, String filter) {
        return context.<List<String>>withProgram(program -> {
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
            
            return strings.stream().skip(offset).limit(limit).collect(Collectors.toList());
        }).orElse(Collections.singletonList("No program loaded"));
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
                    .orElse(false);
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
                .map(func -> {
                    // Decompile function to access high function
                    DecompInterface decomp = new DecompInterface();
                    decomp.openProgram(program);
                    DecompileResults results = decomp.decompileFunction(func, 30, context.getTaskMonitor());
                    
                    if (results == null || !results.decompileCompleted()) {
                        return "Decompilation failed for function " + functionName;
                    }
                    
                    return Optional.ofNullable(results.getHighFunction())
                        .flatMap(highFunction -> Optional.ofNullable(highFunction.getLocalSymbolMap()))
                        .map(localSymbolMap -> {
                            // Check if new name already exists
                            boolean newNameExists = StreamSupport.stream(
                                java.util.Spliterators.spliteratorUnknownSize(localSymbolMap.getSymbols(), java.util.Spliterator.ORDERED), false)
                                .anyMatch(symbol -> symbol.getName().equals(newName));
                                
                            if (newNameExists) {
                                return "Error: A variable with name '" + newName + "' already exists in this function";
                            }
                            
                            // Find the symbol to rename
                            return StreamSupport.stream(
                                java.util.Spliterators.spliteratorUnknownSize(localSymbolMap.getSymbols(), java.util.Spliterator.ORDERED), false)
                                .filter(symbol -> symbol.getName().equals(oldName))
                                .findFirst()
                                .map(highSymbol -> {
                                    int tx = program.startTransaction("Rename variable");
                                    try {
                                        // Check if full commit is required (from the example)
                                        boolean commitRequired = checkFullCommit(highSymbol, results.getHighFunction());
                                        
                                        if (commitRequired) {
                                            ghidra.program.model.pcode.HighFunctionDBUtil.commitParamsToDatabase(
                                                results.getHighFunction(), false,
                                                ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT,
                                                func.getSignatureSource());
                                        }
                                        
                                        // Update the variable name using HighFunctionDBUtil
                                        ghidra.program.model.pcode.HighFunctionDBUtil.updateDBVariable(
                                            highSymbol,
                                            newName,
                                            null,  // Keep existing data type
                                            SourceType.USER_DEFINED
                                        );
                                        
                                        return "Variable renamed successfully";
                                    } catch (Exception e) {
                                        return "Failed to rename variable: " + e.getMessage();
                                    } finally {
                                        program.endTransaction(tx, true);
                                    }
                                })
                                .orElse("Variable '" + oldName + "' not found in function '" + functionName + "'");
                        })
                        .orElse("No local symbol map available for function " + functionName);
                })
                .orElse("Function '" + functionName + "' not found")
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
                    .map(func -> {
                        // Decompile function to get high function
                        DecompInterface decomp = new DecompInterface();
                        decomp.openProgram(program);
                        DecompileResults results = decomp.decompileFunction(func, 30, context.getTaskMonitor());
                        
                        if (results == null || !results.decompileCompleted()) {
                            return "Decompilation failed for function at " + functionAddress;
                        }
                        
                        return Optional.ofNullable(results.getHighFunction())
                            .map(highFunction -> {
                                DataTypeManager dtm = program.getDataTypeManager();
                                
                                ghidra.program.model.pcode.HighSymbol symbol = findSymbolByName(highFunction, variableName);
                                if (symbol == null) {
                                    return "Variable '" + variableName + "' not found in function";
                                }
                                
                                return resolveDataType(dtm, newType)
                                    .map(dataType -> {
                                        try {
                                            // Update the variable type using HighFunctionDBUtil
                                            ghidra.program.model.pcode.HighFunctionDBUtil.updateDBVariable(
                                                symbol,
                                                symbol.getName(),
                                                dataType,
                                                SourceType.USER_DEFINED
                                            );
                                            return "Variable type set successfully to " + dataType.getName();
                                        } catch (Exception e) {
                                            throw new RuntimeException("Failed to update variable: " + e.getMessage(), e);
                                        }
                                    })
                                    .orElse("Could not resolve data type: " + newType);
                            })
                            .orElse("No high function available for " + functionAddress);
                    })
                    .orElse("No function at address: " + functionAddress);
                
            } catch (Exception e) {
                return "Error setting variable type: " + e.getMessage();
            } finally {
                program.endTransaction(tx, true);
            }
        }).orElse("No program loaded");
    }
    
    private ghidra.program.model.pcode.HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        java.util.Iterator<ghidra.program.model.pcode.HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        return StreamSupport.stream(
            java.util.Spliterators.spliteratorUnknownSize(symbols, java.util.Spliterator.ORDERED), false)
            .filter(symbol -> symbol.getName().equals(variableName))
            .findFirst()
            .orElse(null);
    }
    
    private Optional<DataType> resolveDataType(DataTypeManager dtm, String typeName) {
        try {
            // Use Ghidra's built-in C parser - handles pointers, built-ins, and complex types
            ghidra.app.util.cparser.C.CParser parser = new ghidra.app.util.cparser.C.CParser(dtm);
            DataType parsedType = parser.parse(typeName);
            return Optional.ofNullable(parsedType);
        } catch (Exception e) {
            // Fallback using functional approach
            Optional<DataType> directType = Optional.ofNullable(dtm.getDataType("/" + typeName));
            if (directType.isPresent()) {
                return directType;
            }
            return StreamSupport.stream(
                java.util.Spliterators.spliteratorUnknownSize(dtm.getAllDataTypes(), java.util.Spliterator.ORDERED), false)
                .filter(dt -> dt.getName().equalsIgnoreCase(typeName))
                .findFirst();
        }
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
                .orElse("Function not found at address: " + functionAddress)
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
            try {
                Address addr = parseAddress(program, addressStr)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid address: " + addressStr));
                
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
        }).orElse("Error: No program loaded");
    }

    // Helper Methods (Pure Functions)
    // ==============================

    private Stream<Function> streamFunctions(Program program) {
        return StreamSupport.stream(
            program.getFunctionManager().getFunctions(true).spliterator(), false);
    }

    private Optional<Function> findFunctionByName(Program program, String name) {
        return streamFunctions(program)
            .filter(func -> func.getName().equals(name))
            .findFirst();
    }

    private Optional<Function> findFunctionByAddress(Program program, Address address) {
        return Optional.ofNullable(program.getFunctionManager().getFunctionAt(address));
    }

    private Optional<Address> parseAddress(Program program, String addressStr) {
        try {
            return Optional.of(program.getAddressFactory().getAddress(addressStr));
        } catch (Exception e) {
            context.showError("Invalid address format: " + addressStr);
            return Optional.empty();
        }
    }

    private String decompileFunction(Program program, Function function) {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        
        return Optional.of(decomp.decompileFunction(function, 30, context.getTaskMonitor()))
            .filter(DecompileResults::decompileCompleted)
            .map(result -> result.getDecompiledFunction().getC())
            .orElse("Decompilation failed");
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
