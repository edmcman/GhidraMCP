import java.io.File;

import com.lauriewired.GhidraAnalysisService;
import com.lauriewired.context.HeadlessGhidraContext;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

public class FunctionAddressTest {
    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        Object consumer = new Object();
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB("function-address", language,
            language.getDefaultCompilerSpec(), consumer);
        try {
            var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
            int tx = program.startTransaction("Create function");
            try {
                program.getMemory().createInitializedBlock("test", entry, 4096,
                    (byte) 0, TaskMonitor.DUMMY, false);
                program.getFunctionManager().createFunction("target", entry,
                    new AddressSet(entry, entry.add(15)), SourceType.USER_DEFINED);
            } finally {
                program.endTransaction(tx, true);
            }
            var service = new GhidraAnalysisService(new HeadlessGhidraContext(program, TaskMonitor.DUMMY));
            String function = service.getFunctionByAddress("1000");
            check(function.contains("target"), "entry address resolves function");
            check(function.equals(service.getFunctionByAddress("1008")), "interior address resolves same function");
            check(service.getFunctionByAddress("1010").contains("No function"), "outside address fails");
            check(service.getFunctionByAddress("invalid").contains("failed"), "invalid address fails");
            check(service.disassembleFunction("1000").equals(service.disassembleFunction("1008")),
                "disassembly accepts interior address");
            check(service.renameFunctionByAddress("1008", "renamed").isRight(), "rename accepts interior address");
            check(service.getFunctionByAddress("1000").contains("renamed"), "rename targets containing function");
            check(service.setFunctionPrototype("1008", "int renamed(void)").contains("successfully"),
                "prototype accepts interior address");
            System.out.println("Function address regression checks passed");
        } finally {
            program.release(consumer);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
