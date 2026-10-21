// Export priority candidate pairs without renaming functions or accepting roles.
// @category PhoneExit.Vampir
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class InspectVampirReleaseCandidates extends GhidraScript {
    private JsonObject export(Program program, String address, Path out, String label) throws Exception {
        Function function = program.getFunctionManager().getFunctionAt(program.getAddressFactory().getAddress(address));
        if (function == null) throw new IllegalStateException("Missing function " + address);
        JsonObject result = new JsonObject();
        result.addProperty("address", address);
        result.addProperty("body_bytes", function.getBody().getNumAddresses());
        JsonArray instructions = new JsonArray();
        InstructionIterator iterator = program.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            JsonObject row = new JsonObject();
            row.addProperty("address", "0x" + instruction.getAddress());
            row.addProperty("text", instruction.toString());
            row.addProperty("bytes", HexFormat.of().formatHex(instruction.getBytes()));
            JsonArray targets = new JsonArray();
            for (var target : instruction.getFlows()) targets.add("0x" + target);
            row.add("flows", targets); instructions.add(row);
        }
        result.add("instructions", instructions);
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.toggleCCode(true); decompiler.toggleSyntaxTree(false);
            if (!decompiler.openProgram(program)) throw new IllegalStateException(decompiler.getLastMessage());
            DecompileResults c = decompiler.decompileFunction(function, 45, monitor);
            result.addProperty("decompilation_completed", c.decompileCompleted());
            result.addProperty("message", c.getErrorMessage());
            if (c.decompileCompleted() && c.getDecompiledFunction() != null) {
                String filename = label + ".c";
                Files.writeString(out.resolve(filename), c.getDecompiledFunction().getC());
                result.addProperty("pseudocode_file", filename);
            }
        } finally { decompiler.dispose(); }
        return result;
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("candidates.json output");
        JsonObject candidates = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        if (!candidates.get("new_source_sha256").getAsString().equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("New digest mismatch");
        Program source = (Program) state.getProject().getProjectData().getRootFolder().getFile("HistoricalSource")
            .getReadOnlyDomainObject(this, -1, monitor);
        try {
            if (!candidates.get("old_source_sha256").getAsString().equalsIgnoreCase(source.getExecutableSHA256()))
                throw new IllegalStateException("Old digest mismatch");
            Set<String> wanted = Set.of("PktLogin_Write", "PktLogin_Read", "Archive_WriteFString",
                "PktCharacterListResult_Read", "CharacterList_RecordRead", "CharacterList_RequestA",
                "CharacterList_RequestB", "PktCharacterSelect_Write", "PktCharacterSelectResult_Read");
            Map<String, JsonObject> pairs = new TreeMap<>();
            for (JsonElement pass : candidates.getAsJsonArray("passes")) {
                for (JsonElement item : pass.getAsJsonObject().getAsJsonArray("matches")) {
                    JsonObject row = item.getAsJsonObject();
                    String name = row.get("old_analyst_name").getAsString();
                    if (!wanted.contains(name)) continue;
                    if (pairs.containsKey(name) && !pairs.get(name).get("new_address").equals(row.get("new_address")))
                        throw new IllegalStateException("Conflicting priority candidate");
                    pairs.put(name, row);
                }
            }
            Path out = Path.of(args[1]); Files.createDirectories(out);
            JsonArray rows = new JsonArray();
            for (var item : pairs.entrySet()) {
                println("Inspecting candidate " + item.getKey());
                JsonObject pair = new JsonObject(); pair.addProperty("old_analyst_name", item.getKey());
                pair.add("old", export(source, item.getValue().get("old_address").getAsString(), out, item.getKey() + "-old"));
                pair.add("new", export(currentProgram, item.getValue().get("new_address").getAsString(), out, item.getKey() + "-new"));
                rows.add(pair);
            }
            JsonObject report = new JsonObject();
            report.addProperty("old_source_sha256", source.getExecutableSHA256());
            report.addProperty("new_source_sha256", currentProgram.getExecutableSHA256());
            report.addProperty("roles_transferred", false);
            report.add("pairs", rows);
            Files.writeString(out.resolve("details.json"), new GsonBuilder().setPrettyPrinting().create().toJson(report) + "\n");
        } finally { source.release(this); }
    }
}
