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
                (args.length == 3 && !List.of("connected", "scalar").contains(args[2])))
            throw new IllegalArgumentException("Unsupported source or inspection mode");
        Path out = Path.of(args[1]);
        Files.createDirectory(out);
        JsonObject report = new JsonObject();
        report.addProperty("source_sha256", currentProgram.getExecutableSHA256());
        report.addProperty("scalar", 30413);
        report.addProperty("roles_transferred", false);
        JsonArray hits = new JsonArray();
        Map<Address, Function> owners = new TreeMap<>();
        if (args.length == 3 && args[2].equals("connected")) {
            JsonArray tables = new JsonArray();
            // LEA/store bindings in the separately exported new GamePeer ctor.
            for (String text : List.of("1496736c8", "1496736f8")) {
                Address table = currentProgram.getAddressFactory().getAddress(text);
                byte[] raw = new byte[40]; currentProgram.getMemory().getBytes(table, raw);
                int slot = text.equals("1496736f8") ? 24 : 16;
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
            report.add("connected_tables", tables);
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
        for (Function owner : new ArrayList<>(owners.values()))
            for (Function caller : owner.getCallingFunctions(monitor)) owners.put(caller.getEntryPoint(), caller);
        if (owners.size() > 64) throw new IllegalStateException("Owner export bound exceeded");
        JsonArray functions = new JsonArray();
        for (Function function : owners.values()) functions.add(export(function, out));
        report.add("functions", functions);
        Files.writeString(out.resolve("bootstrap.json"), new GsonBuilder().setPrettyPrinting().create().toJson(report) + "\n");
    }
}
