// Inspect literal references for SDK profile migration; no role transfer.
// @category PhoneExit.Vampir
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
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
            {"SdkVersion", "5.2.11", "utf16"},
            {"GameInitSetting", "FNnNetmarbleSDKService::_InitSetting()", "utf16"},
            {"GmcStart", "void __cdecl Netmarble::Service::FGMC2ManagerImpl::Start(void)", "ascii"},
            {"GmcTemplatePath", "/template-groups/", "ascii"},
            {"GmcBuildQuery", "?game=v5&country=G9&build=", "ascii"},
            {"GmcMarketQuery", "&engine=unreal&market=", "ascii"}
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
                disassemble(address);
                Function function = currentProgram.getFunctionManager().getFunctionAt(address);
                boolean created = false;
                if (function == null) {
                    if (!disassemble(address)) throw new IllegalStateException("SDK candidate disassembly failed");
                    function = createFunction(address, null); created = true;
                }
                if (function == null) throw new IllegalStateException("SDK candidate function creation failed");
                CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor);
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
            JsonArray tailModels = new JsonArray();
            String ownerKey = "0x" + owner.getEntryPoint();
            if (source.has("requested_tail_calls") && source.getAsJsonObject("requested_tail_calls").has(ownerKey)) {
                for (JsonElement item : source.getAsJsonObject("requested_tail_calls").getAsJsonArray(ownerKey)) {
                    JsonObject tail = item.getAsJsonObject();
                    Address at = currentProgram.getAddressFactory().getAddress(tail.get("address").getAsString());
                    Address target = currentProgram.getAddressFactory().getAddress(tail.get("target").getAsString());
                    Instruction ins = currentProgram.getListing().getInstructionAt(at);
                    byte[] expected = HexFormat.of().parseHex(tail.get("bytes").getAsString());
                    Function callee = currentProgram.getFunctionManager().getFunctionAt(target);
                    if (ins == null || !ins.getMnemonicString().equalsIgnoreCase("JMP") || expected.length != 5
                        || expected[0] != (byte)0xe9 || !Arrays.equals(ins.getBytes(), expected)
                        || !owner.getBody().contains(at) || callee == null || target.equals(owner.getEntryPoint()))
                        throw new IllegalStateException("Unverified explicit tail-call model at " + at);
                    int displacement = java.nio.ByteBuffer.wrap(expected, 1, 4).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
                    if (!at.add(5L + displacement).equals(target)) throw new IllegalStateException("Tail-call target differs");
                    // Analysis metadata only. The native E9 bytes and PE ranges are unchanged.
                    ins.setFlowOverride(FlowOverride.CALL_RETURN);
                    tailModels.add(tail.deepCopy());
                }
            }
            row.add("tail_call_models", tailModels);
            if (source.has("requested_tail_scans") && source.getAsJsonObject("requested_tail_scans").has(ownerKey)) {
                row.add("linear_tail_scan", source.getAsJsonObject("requested_tail_scans").get(ownerKey).deepCopy());
            }
            // The result-code mapper reached from a selected popup is about 42 KiB.
            // Keep a finite budget for these explicitly referenced functions.
            if (owner.getBody().getNumAddresses() > (args.length >= 4 ? 65536 : 20000)) {
                row.addProperty("skipped", "body_budget"); functions.add(row); continue;
            }
            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.toggleCCode(true); decompiler.toggleSyntaxTree(true);
                if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
                var result = decompiler.decompileFunction(owner, 30, monitor);
                row.addProperty("decompilation_completed", result.decompileCompleted());
                row.addProperty("message", result.getErrorMessage());
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    String filename = "SdkLiteralOwner-" + owner.getEntryPoint() + ".c";
                    Files.writeString(out.resolve(filename), result.getDecompiledFunction().getC());
                    row.addProperty("pseudocode_file", filename);
                }
                if (source.has("requested_unwind_ranges") && result.getHighFunction() != null) {
                    AddressSet permitted = new AddressSet();
                    String key = "0x" + owner.getEntryPoint();
                    for (JsonElement item : source.getAsJsonObject("requested_unwind_ranges").getAsJsonArray(key)) {
                        JsonObject range = item.getAsJsonObject();
                        Address begin = currentProgram.getAddressFactory().getAddress(range.get("begin").getAsString());
                        Address end = currentProgram.getAddressFactory().getAddress(range.get("end").getAsString()).subtract(1);
                        permitted.add(begin, end);
                    }
                    if (permitted.getNumAddresses() > 65536) throw new IllegalStateException("Requested block range budget");
                    var blocks = result.getHighFunction().getBasicBlocks();
                    if (blocks.isEmpty() || blocks.size() > 512) throw new IllegalStateException("Requested block count budget");
                    AddressSet body = new AddressSet(owner.getBody()).intersect(permitted);
                    JsonArray starts = new JsonArray();
                    for (var block : blocks) {
                        Address begin = block.getStart(), end = block.getStop();
                        if (!permitted.contains(begin, end)) throw new IllegalStateException("Decompiler block outside requested unwind ranges");
                        DisassembleCommand command = new DisassembleCommand(begin, permitted, true);
                        command.enableCodeAnalysis(false);
                        command.applyTo(currentProgram, monitor);
                        var last = currentProgram.getListing().getInstructionAt(end);
                        if (last == null || !permitted.contains(begin, last.getMaxAddress()))
                            throw new IllegalStateException("Decompiler block is not fully disassembled");
                        body.add(begin, last.getMaxAddress());
                        starts.add("0x" + begin);
                    }
                    owner.setBody(body);
                    row.add("decompiler_block_starts", starts);
                    row.addProperty("block_coverage_complete", true);
                } else if (source.has("requested_unwind_ranges")) {
                    row.addProperty("block_coverage_complete", false);
                }
            } finally { decompiler.dispose(); }
            row.addProperty("body_bytes", owner.getBody().getNumAddresses());
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
