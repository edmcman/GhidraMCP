package com.lauriewired;

import com.lauriewired.context.GhidraContext;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.data.*;
import ghidra.app.decompiler.*;
import java.util.*;
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
        return context.<List<String>>withProgram(program -> {
            List<String> strings = new ArrayList<>();
            
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (block.isInitialized()) {
                    DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
                    while (it.hasNext()) {
                        Data data = it.next();
                        if (data.hasStringValue()) {
                            String value = data.getDefaultValueRepresentation();
                            strings.add(String.format("%s: %s", data.getAddress(), escapeNonAscii(value)));
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
                            program.getListing().setComment(addr, commentType, comment);
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

    public String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        return context.<String>withProgram(program -> 
            findFunctionByName(program, functionName)
                .map(func -> {
                    Variable[] variables = func.getAllVariables();
                    
                    for (Variable var : variables) {
                        if (var.getName().equals(oldVarName)) {
                            int tx = program.startTransaction("Rename variable");
                            try {
                                var.setName(newVarName, SourceType.USER_DEFINED);
                                return "Variable renamed successfully";
                            } catch (Exception e) {
                                return "Failed to rename variable: " + e.getMessage();
                            } finally {
                                program.endTransaction(tx, true);
                            }
                        }
                    }
                    return "Variable '" + oldVarName + "' not found in function '" + functionName + "'";
                })
                .orElse("Function '" + functionName + "' not found")
        ).orElse("No program loaded");
    }

    // Function Prototype Operations
    // ============================

    public String setFunctionPrototype(String functionName, String returnType, String[] paramTypes, String[] paramNames) {
        return context.<String>withProgram(program ->
            findFunctionByName(program, functionName)
                .map(func -> {
                    int tx = program.startTransaction("Set function prototype");
                    try {
                        DataTypeManager dtm = program.getDataTypeManager();
                        
                        // Get return type
                        DataType retType = findDataType(dtm, returnType);
                        if (retType == null) {
                            return "Unknown return type: " + returnType;
                        }
                        
                        // Set return type
                        func.setReturnType(retType, SourceType.USER_DEFINED);
                        
                        // Build parameter list
                        List<Parameter> params = new ArrayList<>();
                        for (int i = 0; i < paramTypes.length; i++) {
                            DataType paramType = findDataType(dtm, paramTypes[i]);
                            if (paramType == null) {
                                return "Unknown parameter type: " + paramTypes[i];
                            }
                            
                            String paramName = (i < paramNames.length) ? paramNames[i] : "param" + i;
                            params.add(new ParameterImpl(paramName, paramType, program));
                        }
                        
                        // Replace all parameters
                        func.replaceParameters(params, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, 
                            true, SourceType.USER_DEFINED);
                        
                        return "Function prototype updated successfully";
                    } catch (Exception e) {
                        return "Error setting function prototype: " + e.getMessage();
                    } finally {
                        program.endTransaction(tx, true);
                    }
                })
                .orElse("Function '" + functionName + "' not found")
        ).orElse("No program loaded");
    }

    private DataType findDataType(DataTypeManager dtm, String typeName) {
        // Common type mappings
        switch (typeName.toLowerCase()) {
            case "void": return VoidDataType.dataType;
            case "char": case "byte": return CharDataType.dataType;
            case "short": return ShortDataType.dataType;
            case "int": return IntegerDataType.dataType;
            case "long": return LongDataType.dataType;
            case "float": return FloatDataType.dataType;
            case "double": return DoubleDataType.dataType;
            case "pointer": case "ptr": return PointerDataType.dataType;
            default:
                // Try to find in data type manager
                return dtm.getDataType("/" + typeName);
        }
    }

    // Type Creation and Data Export
    // =============================

    public String createStruct(String structName, String[] fieldNames, String[] fieldTypes) {
        return context.<String>withProgram(program -> {
            int tx = program.startTransaction("Create struct");
            try {
                DataTypeManager dtm = program.getDataTypeManager();
                
                // Create structure
                StructureDataType struct = new StructureDataType(structName, 0);
                
                for (int i = 0; i < fieldNames.length && i < fieldTypes.length; i++) {
                    DataType fieldType = findDataType(dtm, fieldTypes[i]);
                    if (fieldType == null) {
                        return "Unknown field type: " + fieldTypes[i];
                    }
                    struct.add(fieldType, fieldNames[i], null);
                }
                
                dtm.addDataType(struct, null);
                return "Struct '" + structName + "' created successfully";
            } catch (Exception e) {
                return "Error creating struct: " + e.getMessage();
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
        StringBuilder result = new StringBuilder();
        result.append("Function: ").append(function.getName()).append(" @ ").append(function.getEntryPoint()).append("\n");
        
        try {
            InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                Instruction inst = instructions.next();
                result.append(inst.getAddress()).append(": ").append(inst.toString()).append("\n");
            }
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
        
        return result.toString();
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
