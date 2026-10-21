// Inspect literal references for SDK profile migration; no role transfer.
// @category PhoneExit.Vampir
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class InspectVampirSdkProfile extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 && args.length < 4) throw new IllegalArgumentException("candidates.json output [references.json functions]");
        JsonObject source = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        if (!source.get("new_source_sha256").getAsString().equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("New source mismatch");
        Path out = Path.of(args[1]); Files.createDirectories(out);
        String[][] queries = {
            {"Market", "nmp", "utf16"}, {"GameCode", "thered", "utf16"},
            {"ClientId", "18e6xn1vuR1lGrvR", "utf16"}, {"Platform", "PC", "utf16"},
            {"GmcBase", "https://apis.netmarble.com/gc2", "ascii"},
            {"SdkVersion", "5.2.11", "utf16"}
        };
        JsonArray literals = new JsonArray(), functions = new JsonArray();
        Map<Address, Function> owners = new TreeMap<>();
        JsonArray nativeReferences = new JsonArray();
        if (args.length >= 4) {
            JsonObject supplied = JsonParser.parseString(Files.readString(Path.of(args[2]))).getAsJsonObject();
            if (!supplied.get("source_sha256").getAsString().equalsIgnoreCase(currentProgram.getExecutableSHA256()))
                throw new IllegalStateException("SDK reference source mismatch");
            Set<String> permitted = new HashSet<>();
            for (JsonElement item : supplied.getAsJsonArray("references"))
                permitted.add(item.getAsJsonObject().get("function").getAsString());
            Set<String> requestedAddresses = new LinkedHashSet<>();
            for (int i = 3; i < args.length; i++) requestedAddresses.addAll(Arrays.asList(args[i].split(",")));
            for (String requested : requestedAddresses) {
                if (!permitted.contains(requested)) throw new IllegalArgumentException("Function absent from SDK references");
                Address address = currentProgram.getAddressFactory().getAddress(requested);
                Function function = currentProgram.getFunctionManager().getFunctionAt(address);
                boolean created = false;
                if (function == null) {
                    if (!disassemble(address)) throw new IllegalStateException("SDK candidate disassembly failed");
                    function = createFunction(address, null); created = true;
                }
                if (function == null) throw new IllegalStateException("SDK candidate function creation failed");
                owners.put(address, function);
                JsonObject selected = new JsonObject(); selected.addProperty("address", requested);
                selected.addProperty("function_created_for_inspection", created); nativeReferences.add(selected);
            }
        }
        for (String[] query : args.length >= 4 ? new String[0][] : queries) {
            byte[] bytes = (query[1] + "\0").getBytes(query[2].equals("utf16") ? StandardCharsets.UTF_16LE : StandardCharsets.US_ASCII);
            Address cursor = currentProgram.getMinAddress();
            int matches = 0;
            while (cursor != null) {
                Address found = currentProgram.getMemory().findBytes(cursor, bytes, null, true, monitor);
                if (found == null) break;
                // A short "PC" suffix occurs inside many unrelated strings.
                // Require a complete UTF-16 literal boundary for this query.
                if (query[0].equals("Platform") && currentProgram.getMemory().getShort(found.subtract(2)) != 0) {
                    cursor = found.add(bytes.length); continue;
                }
                if (++matches > 16) throw new IllegalStateException("Literal occurrence budget: " + query[0]);
                JsonObject literal = new JsonObject(); literal.addProperty("label", query[0]);
                literal.addProperty("text", query[1]); literal.addProperty("encoding", query[2]);
                literal.addProperty("preceding_utf16_nul_required", query[0].equals("Platform"));
                literal.addProperty("address", "0x" + found); literal.addProperty("bytes", HexFormat.of().formatHex(bytes));
                JsonArray references = new JsonArray();
                var refs = currentProgram.getReferenceManager().getReferencesTo(found);
                int count = 0;
                while (refs.hasNext()) {
                    var ref = refs.next();
                    if (++count > 64) throw new IllegalStateException("Literal reference budget: " + query[0]);
                    JsonObject row = new JsonObject(); row.addProperty("from", "0x" + ref.getFromAddress());
                    Function owner = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                    if (owner != null) {
                        row.addProperty("function", "0x" + owner.getEntryPoint());
                        owners.put(owner.getEntryPoint(), owner);
                    }
                    references.add(row);
                }
                literal.add("references", references); literals.add(literal);
                cursor = found.add(bytes.length);
            }
        }
        if (owners.size() > 32) throw new IllegalStateException("SDK function export budget");
        for (Function owner : owners.values()) {
            println("Inspecting SDK literal owner " + owner.getEntryPoint());
            JsonObject row = new JsonObject(); row.addProperty("address", "0x" + owner.getEntryPoint());
            row.addProperty("body_bytes", owner.getBody().getNumAddresses());
            if (owner.getBody().getNumAddresses() > 20000) {
                row.addProperty("skipped", "body_budget"); functions.add(row); continue;
            }
            JsonArray instructions = new JsonArray();
            var iterator = currentProgram.getListing().getInstructions(owner.getBody(), true);
            while (iterator.hasNext()) {
                var ins = iterator.next(); JsonObject instruction = new JsonObject();
                instruction.addProperty("address", "0x" + ins.getAddress());
                instruction.addProperty("text", ins.toString());
                instruction.addProperty("bytes", HexFormat.of().formatHex(ins.getBytes()));
                JsonArray refs = new JsonArray();
                for (var ref : ins.getReferencesFrom()) refs.add("0x" + ref.getToAddress());
                instruction.add("references", refs); instructions.add(instruction);
            }
            row.add("instructions", instructions);
            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.toggleCCode(true); decompiler.toggleSyntaxTree(false);
                if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
                var result = decompiler.decompileFunction(owner, 30, monitor);
                row.addProperty("decompilation_completed", result.decompileCompleted());
                row.addProperty("message", result.getErrorMessage());
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    String filename = "SdkLiteralOwner-" + owner.getEntryPoint() + ".c";
                    Files.writeString(out.resolve(filename), result.getDecompiledFunction().getC());
                    row.addProperty("pseudocode_file", filename);
                }
            } finally { decompiler.dispose(); }
            functions.add(row);
        }
        JsonObject report = new JsonObject();
        report.addProperty("new_source_sha256", currentProgram.getExecutableSHA256());
        report.addProperty("roles_transferred", false);
        report.add("literals", literals); report.add("functions", functions);
        report.add("native_reference_candidates", nativeReferences);
        Files.writeString(out.resolve("details.json"), new GsonBuilder().setPrettyPrinting().create().toJson(report) + "\n");
    }
}
