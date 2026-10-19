// Export source-bound function pseudocode without launching the game.
// @category PhoneExit.Vampir
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class ExportVampirFunctions extends GhidraScript {
    private Address address(String value) { return toAddr(Long.decode(value)); }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("manifest.json output-directory");
        JsonObject manifest = JsonParser.parseString(Files.readString(Path.of(args[0]), StandardCharsets.UTF_8)).getAsJsonObject();
        String expected = manifest.get("source_sha256").getAsString();
        if (!expected.equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("Imported program SHA256 does not match manifest");
        Path out = Path.of(args[1]); Files.createDirectories(out);
        JsonArray seeds = manifest.getAsJsonArray("functions");
        // Establish known boundaries/names first, so calls among selected functions resolve.
        for (JsonElement item : seeds) {
            JsonObject seed = item.getAsJsonObject();
            Address entry = address(seed.get("address").getAsString());
            AddressSet body = new AddressSet();
            for (JsonElement rangeItem : seed.getAsJsonArray("ranges")) {
                JsonObject r = rangeItem.getAsJsonObject();
                body.addRange(address(r.get("start").getAsString()), address(r.get("end_exclusive").getAsString()).subtract(1));
            }
            DisassembleCommand dis = new DisassembleCommand(entry, body, true);
            if (!dis.applyTo(currentProgram, monitor)) println("Disassembly note: " + seed.get("name") + ": " + dis.getStatusMsg());
            Function f = currentProgram.getFunctionManager().getFunctionAt(entry);
            if (f == null) f = currentProgram.getFunctionManager().createFunction(seed.get("name").getAsString(), entry, body, SourceType.USER_DEFINED);
            else { f.setName(seed.get("name").getAsString(), SourceType.USER_DEFINED); f.setBody(body); }
        }
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true); decompiler.toggleSyntaxTree(false);
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
        JsonArray exported = new JsonArray();
        try {
            for (JsonElement item : seeds) {
                monitor.checkCancelled();
                JsonObject seed = item.getAsJsonObject();
                Function f = currentProgram.getFunctionManager().getFunctionAt(address(seed.get("address").getAsString()));
                JsonObject row = new JsonObject();
                row.addProperty("name", f.getName()); row.addProperty("address", "0x" + f.getEntryPoint());
                row.addProperty("name_origin", "analyst_hint_from_shared_evidence");
                println("Decompiling " + f.getName() + " at " + f.getEntryPoint());
                DecompileResults result = decompiler.decompileFunction(f, 45, monitor);
                row.addProperty("completed", result.decompileCompleted());
                row.addProperty("message", result.getErrorMessage());
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    String filename = f.getName() + ".c";
                    Files.writeString(out.resolve(filename), result.getDecompiledFunction().getC(), StandardCharsets.UTF_8);
                    row.addProperty("pseudocode_file", filename);
                }
                JsonArray calls = new JsonArray();
                InstructionIterator instructions = currentProgram.getListing().getInstructions(f.getBody(), true);
                int count = 0;
                while (instructions.hasNext()) {
                    Instruction instruction = instructions.next(); count++;
                    if (!instruction.getFlowType().isCall()) continue;
                    JsonObject call = new JsonObject();
                    call.addProperty("address", "0x" + instruction.getAddress());
                    call.addProperty("instruction", instruction.toString());
                    JsonArray targets = new JsonArray();
                    for (Address target : instruction.getFlows()) {
                        JsonObject t = new JsonObject(); t.addProperty("address", "0x" + target);
                        Function callee = currentProgram.getFunctionManager().getFunctionAt(target);
                        if (callee != null) t.addProperty("name", callee.getName());
                        targets.add(t);
                    }
                    call.add("targets", targets); calls.add(call);
                }
                row.addProperty("instruction_count", count); row.add("calls", calls); exported.add(row);
            }
        } finally { decompiler.dispose(); }
        JsonObject report = new JsonObject();
        report.addProperty("schema_version", 1); report.addProperty("source_sha256", expected);
        report.addProperty("ghidra_version", Application.getApplicationVersion());
        report.addProperty("java_version", System.getProperty("java.version"));
        report.addProperty("whole_program_analysis", false); report.addProperty("game_executed", false);
        report.add("functions", exported);
        Files.writeString(out.resolve("functions.json"), new GsonBuilder().setPrettyPrinting().create().toJson(report) + "\n", StandardCharsets.UTF_8);
        println("Vampir export complete: " + exported.size() + " functions");
    }
}
