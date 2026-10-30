import java.io.File;

import com.lauriewired.GhidraAnalysisService;
import com.lauriewired.context.HeadlessGhidraContext;
import ghidra.GhidraApplicationLayout;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

public class ScriptCompilationTest {
    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        GhidraScriptUtil.getUserScriptDirectory().getFile(false).mkdirs();
        GhidraScriptUtil.acquireBundleHostReference();
        Object consumer = new Object();
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB("script-test", language, language.getDefaultCompilerSpec(), consumer);
        try {
            var service = new GhidraAnalysisService(new HeadlessGhidraContext(program, TaskMonitor.DUMMY));
            String result = service.runScript("BrokenScript.java", "public class BrokenScript { syntax error }");
            if (!result.contains("Script compilation failed") || !result.contains("BrokenScript.java") ||
                !result.contains("error")) {
                throw new AssertionError("Compilation diagnostics missing: " + result);
            }
            System.out.println("Script compilation regression checks passed");
        } finally {
            program.release(consumer);
            GhidraScriptUtil.releaseBundleHostReference();
        }
    }
}
