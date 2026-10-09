import java.io.File;

import com.lauriewired.GhidraAnalysisService;
import com.lauriewired.context.HeadlessGhidraContext;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Data;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

/** Integration regression checks against an in-memory Ghidra program. */
public class DataItemTypesTest {
    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        Object consumer = new Object();
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB("data-item-types", language,
            language.getDefaultCompilerSpec(), consumer);
        try {
            var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
            int tx = program.startTransaction("Test setup");
            try {
                program.getMemory().createInitializedBlock("test", address, 4096,
                    (byte) 0, TaskMonitor.DUMMY, false);
            } finally {
                program.endTransaction(tx, true);
            }
            var service = new GhidraAnalysisService(new HeadlessGhidraContext(program, TaskMonitor.DUMMY));

            // ushort is a built-in even when it has not been added to the program's type manager.
            check(program.getDataTypeManager().getDataType("/ushort") == null,
                "ushort should not already exist in the program");
            check(service.createOrUpdateDataItem("1000", "ushort[222]", "words").isRight(),
                "create ushort[222]");
            Data data = program.getListing().getDefinedDataAt(address);
            check(data.getDataType() instanceof Array, "array type");
            Array array = (Array) data.getDataType();
            check(array.getNumElements() == 222 && array.getElementLength() == 2 && data.getLength() == 444,
                "222 unsigned short elements occupying 444 bytes");
            check(array.getDataType() instanceof UnsignedShortDataType, "unsigned element type");
            check("words".equals(data.getLabel()), "array label");

            tx = program.startTransaction("Add custom typedef");
            try {
                program.getDataTypeManager().addDataType(new TypedefDataType(
                    new CategoryPath("/test"), "CustomWord", UnsignedShortDataType.dataType), null);
            } finally {
                program.endTransaction(tx, true);
            }

            String[] types = {"ushort", "unsigned short[222]", "ushort[2][3]", "ushort *[3]", "CustomWord[222]"};
            int[] lengths = {2, 444, 12, 24, 444};
            for (int i = 0; i < types.length; i++) {
                check(service.createOrUpdateDataItem("1000", types[i], null).isRight(), "update " + types[i]);
                data = program.getListing().getDefinedDataAt(address);
                check(data.getLength() == lengths[i], "length of " + types[i]);
                check("words".equals(data.getLabel()), "preserve label for " + types[i]);
                if (types[i].equals("ushort[2][3]")) {
                    Array outer = (Array) data.getDataType();
                    check(outer.getNumElements() == 2 && outer.getDataType() instanceof Array,
                        "outer array dimension");
                    check(((Array) outer.getDataType()).getNumElements() == 3, "inner array dimension");
                }
                if (types[i].equals("ushort *[3]")) {
                    check(((Array) data.getDataType()).getDataType() instanceof Pointer,
                        "pointer array elements");
                }
            }
            array = (Array) data.getDataType();
            check(array.getDataType() instanceof TypeDef, "preserve custom typedef");

            for (String invalid : new String[] {"MissingType[222]", "ushort[-1]", "ushort[abc]"}) {
                check(service.createOrUpdateDataItem("1000", invalid, "changed").isLeft(), "reject " + invalid);
                data = program.getListing().getDefinedDataAt(address);
                check(data.getLength() == 444 && "words".equals(data.getLabel()),
                    "failed request preserves data and label");
            }
            check(service.createOrUpdateDataItem("1000", null, "renamed").isRight(), "rename only");
            check("renamed".equals(program.getListing().getDefinedDataAt(address).getLabel()), "new label");
            System.out.println("Data item type regression checks passed");
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
