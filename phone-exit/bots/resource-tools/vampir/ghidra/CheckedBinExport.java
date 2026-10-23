// Verify the imported executable identity before producing comparison candidates.
// @category PhoneExit
import ghidra.app.script.GhidraScript;

public class CheckedBinExport extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || !args[0].matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Expected full source SHA256 and output path");
        }
        if (!args[0].equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            throw new IllegalArgumentException("Imported program SHA256 differs from source");
        }
        runScript("BinExport.java", new String[] {args[1], "Prepend Namespace to Function Names"});
    }
}
