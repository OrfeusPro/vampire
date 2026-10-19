// Discover assembler helper boundaries with Ghidra's own flow analysis.
// @category PhoneExit.Vampir
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.block.*;
import java.util.Iterator;
import java.util.HashSet;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class ExportVampirMath extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=2)throw new IllegalArgumentException("source-sha256 output-directory");
        if(!args[0].equalsIgnoreCase(currentProgram.getExecutableSHA256()))throw new IllegalStateException("Source SHA mismatch");
        Path out=Path.of(args[1]);Files.createDirectories(out);
        long[] entries={0x141444d00L,0x1487969e0L};
        String[] names={"Math_GuardedRemainder","Math_SSE2SinCos"};
        JsonArray rows=new JsonArray();
        DecompInterface decompiler=new DecompInterface();
        decompiler.toggleCCode(true);decompiler.toggleSyntaxTree(true);
        if(!decompiler.openProgram(currentProgram))throw new IllegalStateException(decompiler.getLastMessage());
        try {
            for(int i=0;i<entries.length;i++) {
                Address entry=toAddr(entries[i]);disassemble(entry);
                Function f=getFunctionAt(entry);
                if(f==null)f=createFunction(entry,names[i]);
                else f.setName(names[i],SourceType.USER_DEFINED);
                if(f==null)throw new IllegalStateException("Cannot discover function at "+entry);
                JsonObject row=new JsonObject();row.addProperty("name",names[i]);row.addProperty("address","0x"+entry);
                DecompileResults result=decompiler.decompileFunction(f,45,monitor);
                row.addProperty("completed",result.decompileCompleted());row.addProperty("message",result.getErrorMessage());
                if(!result.decompileCompleted() || result.getHighFunction()==null)throw new IllegalStateException("Math decompilation failed: "+names[i]);
                // Assembly helpers tail-merge code outside the initial Function.
                // P-code blocks can span distant tail targets; never fill their
                // min/max gap. Ask Ghidra for machine basic blocks at reached PCs.
                AddressSet discovered=new AddressSet(f.getBody());
                BasicBlockModel blocks=new BasicBlockModel(currentProgram);
                HashSet<Address> visited=new HashSet<>();
                Iterator<PcodeOpAST> ops=result.getHighFunction().getPcodeOps();
                while(ops.hasNext()) {
                    Address pc=ops.next().getSeqnum().getTarget();
                    if(!pc.isMemoryAddress() || !visited.add(pc))continue;
                    if(getInstructionContaining(pc)==null)disassemble(pc);
                    CodeBlock block=blocks.getFirstCodeBlockContaining(pc,monitor);
                    if(block==null)throw new IllegalStateException("Missing machine block at "+pc);
                    discovered.add(block);
                }
                if(discovered.getNumAddresses()>65536)throw new IllegalStateException("Discovered math body exceeds local bound");
                JsonArray ranges=new JsonArray();
                AddressRangeIterator iterator=discovered.getAddressRanges();
                while(iterator.hasNext()) {
                    AddressRange range=iterator.next();JsonObject r=new JsonObject();
                    r.addProperty("start","0x"+range.getMinAddress());
                    r.addProperty("end_exclusive","0x"+range.getMaxAddress().add(1));ranges.add(r);
                }
                row.add("ranges",ranges);
                Files.writeString(out.resolve(names[i]+".c"),result.getDecompiledFunction().getC(),StandardCharsets.UTF_8);
                rows.add(row);
            }
        } finally {decompiler.dispose();}
        JsonObject report=new JsonObject();report.addProperty("source_sha256",args[0]);
        report.addProperty("ghidra_version",Application.getApplicationVersion());
        report.addProperty("body_origin","Ghidra disassemble/createFunction flow discovery; native paths require separate verification");
        report.add("functions",rows);
        Files.writeString(out.resolve("functions.json"),new GsonBuilder().setPrettyPrinting().create().toJson(report)+"\n",StandardCharsets.UTF_8);
    }
}
