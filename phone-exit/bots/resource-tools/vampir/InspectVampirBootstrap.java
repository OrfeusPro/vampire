// Inspect the observed bootstrap scalar in an existing saved Ghidra program.
// No function renaming, role transfer, program execution or injected code.
// @category PhoneExit.Vampir
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class InspectVampirBootstrap extends GhidraScript {
    private JsonObject export(Function function, Path out) throws Exception {
        JsonObject row = new JsonObject();
        String address = "0x" + function.getEntryPoint();
        row.addProperty("address", address);
        JsonArray instructions = new JsonArray();
        var it = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            JsonObject item = new JsonObject();
            item.addProperty("address", "0x" + ins.getAddress());
            item.addProperty("text", ins.toString());
            item.addProperty("bytes", HexFormat.of().formatHex(ins.getBytes()));
            JsonArray flows = new JsonArray();
            for (Address target : ins.getFlows()) flows.add("0x" + target);
            item.add("flows", flows);
            instructions.add(item);
        }
        row.add("instructions", instructions);
        JsonArray callers = new JsonArray();
        for (Function f : function.getCallingFunctions(monitor)) callers.add("0x" + f.getEntryPoint());
        row.add("callers", callers);
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.toggleSyntaxTree(false);
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
            var result = decompiler.decompileFunction(function, 45, monitor);
            row.addProperty("completed", result.decompileCompleted());
            row.addProperty("message", result.getErrorMessage());
            if (result.decompileCompleted() && result.getDecompiledFunction() != null)
                Files.writeString(out.resolve(address + ".c"), result.getDecompiledFunction().getC());
        } finally { decompiler.dispose(); }
        return row;
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if ((args.length != 2 && args.length != 3) || !args[0].equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalArgumentException("Expected matching source SHA and new output directory");
        if (!args[0].equalsIgnoreCase("98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e") ||
                (args.length == 3 && !List.of("connected", "scalar", "send", "lifecycle", "ping").contains(args[2])))
            throw new IllegalArgumentException("Unsupported source or inspection mode");
        Path out = Path.of(args[1]);
        Files.createDirectory(out);
        JsonObject report = new JsonObject();
        report.addProperty("source_sha256", currentProgram.getExecutableSHA256());
        report.addProperty("new_source_sha256", currentProgram.getExecutableSHA256());
        report.addProperty("scalar", 30413);
        report.addProperty("roles_transferred", false);
        JsonArray hits = new JsonArray();
        Map<Address, Function> owners = new TreeMap<>();
        if (args.length == 3 && args[2].equals("ping")) {
            JsonArray references = new JsonArray();
            JsonArray literals = new JsonArray();
            byte[] name = "PktPing\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Address cursor = currentProgram.getMinAddress();
            while (cursor != null) {
                Address found = currentProgram.getMemory().findBytes(cursor, name, null, true, monitor);
                if (found == null) break;
                JsonObject literal = new JsonObject();
                literal.addProperty("label", "PktPing");literal.addProperty("address", "0x" + found);
                literal.addProperty("bytes", HexFormat.of().formatHex(name));literals.add(literal);
                var refs = currentProgram.getReferenceManager().getReferencesTo(found);
                while (refs.hasNext()) {
                    var ref = refs.next();
                    Function getter = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                    JsonObject item = new JsonObject();
                    item.addProperty("literal", "0x" + found); item.addProperty("reference", "0x" + ref.getFromAddress());
                    if (getter != null) {
                        item.addProperty("getter_candidate", "0x" + getter.getEntryPoint());
                        owners.put(getter.getEntryPoint(), getter);
                        var tableRefs = currentProgram.getReferenceManager().getReferencesTo(getter.getEntryPoint());
                        JsonArray tables = new JsonArray();
                        while (tableRefs.hasNext()) {
                            Address slot = tableRefs.next().getFromAddress();
                            if (currentProgram.getListing().getInstructionContaining(slot) != null) continue;
                            Address table = slot.subtract(0x38);
                            JsonObject t = new JsonObject();t.addProperty("candidate_table", "0x" + table);
                            byte[] raw = new byte[64]; currentProgram.getMemory().getBytes(table, raw);
                            t.addProperty("bytes", HexFormat.of().formatHex(raw));
                            var ctorRefs = currentProgram.getReferenceManager().getReferencesTo(table);
                            JsonArray uses = new JsonArray();
                            while (ctorRefs.hasNext()) {
                                Address use = ctorRefs.next().getFromAddress();
                                Function ctor = currentProgram.getFunctionManager().getFunctionContaining(use);
                                if (ctor == null) continue;
                                JsonObject u = new JsonObject();u.addProperty("reference", "0x" + use);u.addProperty("owner", "0x" + ctor.getEntryPoint());uses.add(u);
                                owners.put(ctor.getEntryPoint(), ctor);
                                for (Function caller : ctor.getCallingFunctions(monitor)) owners.put(caller.getEntryPoint(), caller);
                            }
                            t.add("table_uses", uses);tables.add(t);
                        }
                        item.add("candidate_tables", tables);
                    }
                    references.add(item);
                }
                cursor = found.add(name.length);
            }
            report.add("ping_name_references", references);
            report.add("literals", literals);
        } else if (args.length == 3 && List.of("connected", "send", "lifecycle").contains(args[2])) {
            JsonArray tables = new JsonArray();
            // LEA/store bindings in the separately exported new GamePeer ctor.
            // Game wrapper table is stored by Network_PeersConstruct 1467cda10.
            boolean send = List.of("send", "lifecycle").contains(args[2]);
            List<String> bindings = args[2].equals("lifecycle") ? List.of("149dcb358:08", "149dcb358:18", "149dcb358:20") : send ? List.of("149dcb358:30", "149dcb358:38", "149dcb358:40", "149dcb358:48") : List.of("1496736c8:10", "1496736f8:18");
            for (String binding : bindings) {
                String text = binding.split(":")[0];
                int slot = Integer.parseInt(binding.split(":")[1], 16);
                Address table = currentProgram.getAddressFactory().getAddress(text);
                byte[] raw = new byte[send ? 80 : 40]; currentProgram.getMemory().getBytes(table, raw);
                Address target = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(currentProgram.getMemory().getLong(table.add(slot)));
                JsonObject item = new JsonObject();
                item.addProperty("table", "0x" + table); item.addProperty("bytes", HexFormat.of().formatHex(raw));
                item.addProperty("slot", slot); item.addProperty("target", "0x" + target); tables.add(item);
                Function function = currentProgram.getFunctionManager().getFunctionAt(target);
                if (function == null) {
                    boolean decoded = disassemble(target);
                    item.addProperty("disassembled_for_inspection", decoded);
                    if (decoded) function = createFunction(target, null);
                    item.addProperty("function_created_for_inspection", function != null);
                }
                if (function != null) owners.put(target, function);
            }
            report.add(send ? "send_tables" : "connected_tables", tables);
            if (send) {
                for (Function function : new ArrayList<>(owners.values()))
                    if (List.of("1467d0a70", "1467d0af0", "1467cec60").contains(function.getEntryPoint().toString()))
                        for (Function callee : function.getCalledFunctions(monitor)) owners.put(callee.getEntryPoint(), callee);
            }
        } else {
        Address cursor = currentProgram.getMinAddress();
        byte[] pattern = {(byte)0xcd, (byte)0x76};
        int matches = 0;
        while (cursor != null) {
            monitor.checkCancelled();
            Address found = currentProgram.getMemory().findBytes(cursor, pattern, null, true, monitor);
            if (found == null) break;
            if (++matches > 8192) throw new IllegalStateException("Scalar search bound exceeded");
            Instruction ins = currentProgram.getListing().getInstructionContaining(found);
            if (ins != null) {
                boolean scalar = false;
                for (int op = 0; op < ins.getNumOperands(); op++)
                    for (Object value : ins.getOpObjects(op))
                        if (value instanceof Scalar && (((Scalar)value).getUnsignedValue() & 65535) == 30413) scalar = true;
                if (scalar) {
                    JsonObject hit = new JsonObject();
                    hit.addProperty("address", "0x" + ins.getAddress());
                    hit.addProperty("text", ins.toString());
                    Function owner = currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress());
                    if (owner != null) {
                        hit.addProperty("owner", "0x" + owner.getEntryPoint());
                        owners.put(owner.getEntryPoint(), owner);
                    }
                    hits.add(hit);
                }
            }
            cursor = found.add(2);
        }
        report.addProperty("byte_matches", matches);
        report.add("scalar_instructions", hits);
        JsonArray wireHits = new JsonArray();
        // The SHA-checked reference contains an empty, CRC-valid 11-byte frame.
        // Search complete bytes and packed immediate fragments, without treating
        // a byte coincidence as a packet role.
        for (String hex : args.length == 3 && args[2].equals("scalar") ? List.<String>of() : List.of("0b000082793f25040eb39a", "0b000082793f2504", "82793f25040eb39a", "040eb39a")) {
            byte[] bytes = HexFormat.of().parseHex(hex);
            cursor = currentProgram.getMinAddress();
            int count = 0;
            while (cursor != null) {
                Address found = currentProgram.getMemory().findBytes(cursor, bytes, null, true, monitor);
                if (found == null) break;
                if (++count > 256) throw new IllegalStateException("Wire fragment search bound exceeded");
                JsonObject hit = new JsonObject();
                hit.addProperty("pattern", hex); hit.addProperty("address", "0x" + found);
                Instruction instruction = currentProgram.getListing().getInstructionContaining(found);
                if (instruction != null) {
                    hit.addProperty("instruction", instruction.toString());
                    Function owner = currentProgram.getFunctionManager().getFunctionContaining(instruction.getAddress());
                    if (owner != null) {
                        hit.addProperty("owner", "0x" + owner.getEntryPoint());
                        owners.put(owner.getEntryPoint(), owner);
                    }
                }
                JsonArray refs = new JsonArray();
                for (int offset = 0; offset < bytes.length; offset++) {
                    var iterator = currentProgram.getReferenceManager().getReferencesTo(found.add(offset));
                    while (iterator.hasNext()) {
                        var ref = iterator.next();
                        JsonObject item = new JsonObject();
                        item.addProperty("from", "0x" + ref.getFromAddress());
                        Function owner = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                        if (owner != null) {
                            item.addProperty("owner", "0x" + owner.getEntryPoint());
                            owners.put(owner.getEntryPoint(), owner);
                        }
                        refs.add(item);
                    }
                }
                hit.add("references", refs); wireHits.add(hit);
                cursor = found.add(bytes.length);
            }
        }
        report.add("wire_fragment_candidates", wireHits);
        }
        // One caller level only: a bound, not a full call graph.
        if (!(args.length == 3 && List.of("send", "lifecycle", "ping").contains(args[2])))
            for (Function owner : new ArrayList<>(owners.values()))
                for (Function caller : owner.getCallingFunctions(monitor)) owners.put(caller.getEntryPoint(), caller);
        if (owners.size() > 64) throw new IllegalStateException("Owner export bound exceeded");
        JsonArray functions = new JsonArray();
        for (Function function : owners.values()) functions.add(export(function, out));
        report.add("functions", functions);
        Files.writeString(out.resolve("bootstrap.json"), new GsonBuilder().setPrettyPrinting().create().toJson(report) + "\n");
    }
}
