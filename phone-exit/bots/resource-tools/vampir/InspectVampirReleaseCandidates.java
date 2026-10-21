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
        JsonObject result = new JsonObject();
        result.addProperty("address", address);
        if (function == null) {
            result.addProperty("function_missing", true);
            return result;
        }
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
        if (args.length != 2 && args.length != 3) throw new IllegalArgumentException("candidates.json output [dependencies]");
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
            JsonArray tables = new JsonArray();
            if (args.length == 3) {
                if (!args[2].equals("dependencies")) throw new IllegalArgumentException("Unknown mode");
                pairs.clear();
                String[][] dependencies = {
                    {"NestedRead_ThunkCandidate", "0x144aa68b0", "0x144aae4e0"},
                    {"CharacterList_RecordConstruct", "0x14577d3d0", "0x145784b10"},
                    {"CharacterList_RecordRead", "0x145781c80", "0x1457897d0"},
                    {"CharacterList_Nested68Read", "0x14578dfa0", "0x145795e90"},
                    {"CharacterList_AppearanceRead", "0x1457812a0", "0x145788d00"},
                    {"CharacterList_AppearanceArrayResize", "0x1456b60e0", "0x1456bb730"},
                    {"Archive_ReadScalar20", "0x144aa5b90", "0x144aad7c0"},
                    {"CharacterList_OptionalRead", "0x1456bf640", "0x1456c42d0"},
                    {"Record_TimeBaseRead", "0x1457f0a90", "0x1457fefb0"},
                    {"CharacterList_ResultRead", "0x1456d8d80", "0x1456dcf00"},
                    {"RecordNested38_ConstructCandidate", "0x1457eca60", "0x1457a47d0"},
                    {"RecordNested38_BaseCandidate", "0x1457eca60", "0x1457fedc0"},
                    {"Archive_ReadFString", "0x144aa66f0", "0x144aae320"},
                    {"Archive_ReadStdString", "0x144aa5ab0", "0x144aad6e0"},
                    {"UTF8_LengthCandidate", "0x141446940", "0x14144c520"},
                    {"UTF8_DecodeWrapperCandidate", "0x141440ba0", "0x141446780"},
                    {"UTF8_DecodeCoreCandidate", "0x141436230", "0x14143be10"},
                    {"UTF8_DecodeScalarCandidate", "0x141435ea0", "0x14143ba80"},
                    {"FString_AssignCandidate", "0x141421dd0", "0x141427890"},
                    {"Archive_ReadArray", "0x144aa5c50", "0x144aad880"},
                    {"Archive_InputConstructCandidate", "0x144aa6260", "0x144aad4e0"},
                    {"Archive_BaseInputConstructCandidate", "0x144aa5850", "0x144aae160"},
                    {"Archive_ReadU16Candidate", "0x144aa5970", "0x144aad5a0"},
                    {"Archive_ReadU32Candidate", "0x144aa59c0", "0x144aad5f0"},
                    {"Archive_ReadU64Candidate", "0x144aa5bc0", "0x144aad7f0"},
                    {"Archive_ReadBoolCandidate", "0x144aa5c10", "0x144aad840"},
                    {"Archive_ReadByteCandidate", "0x144aa5960", "0x144aad590"},
                    {"Archive_ReadRawCandidate", "0x144aa5ce0", "0x144aad910"},
                    {"CharacterList_ClearCandidate", "0x1456d32e0", "0x1456d6f70"},
                    {"CharacterList_ResizeCandidate", "0x1420e2ac0", "0x1420e88c0"}
                };
                for (String[] dependency : dependencies) {
                    JsonObject row = new JsonObject(); row.addProperty("old_address", dependency[1]);
                    row.addProperty("new_address", dependency[2]); pairs.put(dependency[0], row);
                }
                String[] addresses = {"0x1498d90a0", "0x14992adf0"};
                Program[] programs = {source, currentProgram};
                for (int side = 0; side < 2; side++) {
                    JsonObject table = new JsonObject(); table.addProperty("side", side == 0 ? "old" : "new");
                    table.addProperty("address", addresses[side]);
                    JsonArray words = new JsonArray();
                    var address = programs[side].getAddressFactory().getAddress(addresses[side]);
                    for (int i = 0; i < 4; i++) {
                        long value = programs[side].getMemory().getLong(address.add(i * 8));
                        words.add("0x" + Long.toHexString(value));
                        // Table extent is unknown. Export targets as observations, not confirmed slots.
                        if (side == 1) {
                            String name = "ListCallbackObservedWord" + i;
                            JsonObject pair = new JsonObject();
                            long oldValue = source.getMemory().getLong(source.getAddressFactory().getAddress(addresses[0]).add(i * 8));
                            pair.addProperty("old_address", "0x" + Long.toHexString(oldValue));
                            pair.addProperty("new_address", "0x" + Long.toHexString(value));
                            pairs.put(name, pair);
                        }
                    }
                    table.add("observed_words", words); tables.add(table);
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
            report.add("observed_tables", tables);
            JsonArray archiveReferences = new JsonArray();
            for (String tableAddress : new String[]{"0x1496726a8", "0x149672840"}) {
                var refs = currentProgram.getReferenceManager().getReferencesTo(currentProgram.getAddressFactory().getAddress(tableAddress));
                while (refs.hasNext()) {
                    var ref = refs.next(); JsonObject row = new JsonObject();
                    row.addProperty("table", tableAddress); row.addProperty("from", "0x" + ref.getFromAddress());
                    var owner = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                    if (owner != null) row.addProperty("containing_function", "0x" + owner.getEntryPoint());
                    archiveReferences.add(row);
                }
            }
            report.add("observed_archive_references", archiveReferences);
            report.add("pairs", rows);
            Files.writeString(out.resolve("details.json"), new GsonBuilder().setPrettyPrinting().create().toJson(report) + "\n");
        } finally { source.release(this); }
    }
}
