// Read-only candidate correlation; never accept matches or transfer semantic roles.
// @category PhoneExit.Vampir
import ghidra.app.util.headless.HeadlessScript;
import ghidra.base.project.GhidraProject;
import ghidra.feature.vt.api.correlator.program.*;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.framework.model.*;
import ghidra.program.model.listing.*;
import com.google.gson.*;
import java.nio.file.*;

public class CompareVampirRelease extends HeadlessScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 5) throw new IllegalArgumentException("old-project-dir old-project old-sha new-sha output");
        if (!args[3].equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("New program digest mismatch");
        DomainFolder root = state.getProject().getProjectData().getRootFolder();
        GhidraProject historical = GhidraProject.openProject(args[0], args[1], false);
        VTSession session = null;
        try {
            Program source = historical.openProgram("/", currentProgram.getName(), true);
            if (!args[2].equalsIgnoreCase(source.getExecutableSHA256()))
                throw new IllegalStateException("Historical program digest mismatch");
            JsonObject result = new JsonObject();
            result.addProperty("old_source_sha256", source.getExecutableSHA256());
            result.addProperty("new_source_sha256", currentProgram.getExecutableSHA256());
            result.addProperty("analysis_timed_out", analysisTimeoutOccurred());
            result.addProperty("old_function_count", source.getFunctionManager().getFunctionCount());
            result.addProperty("new_function_count", currentProgram.getFunctionManager().getFunctionCount());
            result.addProperty("matches_accepted", false);
            result.addProperty("roles_transferred", false);
            result.addProperty("scope", "Ghidra exact correlators; old selected functions versus new analyzed functions; candidates only");
            // End the script transaction before VT acquires program/session locks.
            end(true);
            session = new VTSessionDB("ReleaseCandidates", source, currentProgram, this);
            root.createFile("ReleaseCandidates", session, monitor);
            int tx = session.startTransaction("Find candidates without accepting");
            JsonArray passes = new JsonArray();
            try {
                VTProgramCorrelatorFactory[] factories = {
                    new ExactMatchBytesProgramCorrelatorFactory(),
                    new ExactMatchInstructionsProgramCorrelatorFactory()
                };
                for (VTProgramCorrelatorFactory factory : factories) {
                    println("Correlating: " + factory.getName());
                    VTProgramCorrelator correlator = factory.createCorrelator(source,
                        source.getMemory().getLoadedAndInitializedAddressSet(), currentProgram,
                        currentProgram.getMemory().getLoadedAndInitializedAddressSet(), factory.createDefaultOptions());
                    VTMatchSet matches = correlator.correlate(session, monitor);
                    JsonObject pass = new JsonObject();
                    pass.addProperty("correlator", factory.getName());
                    JsonArray rows = new JsonArray();
                    for (VTMatch match : matches.getMatches()) {
                        JsonObject row = new JsonObject();
                        row.addProperty("old_address", "0x" + match.getSourceAddress());
                        row.addProperty("new_address", "0x" + match.getDestinationAddress());
                        Function old = source.getFunctionManager().getFunctionAt(match.getSourceAddress());
                        row.addProperty("old_analyst_name", old.getName());
                        row.addProperty("source_length", match.getSourceLength());
                        row.addProperty("destination_length", match.getDestinationLength());
                        row.addProperty("confidence", match.getConfidenceScore().getScore());
                        rows.add(row);
                    }
                    pass.add("matches", rows); passes.add(pass);
                    println("Candidates: " + rows.size());
                }
            } finally { session.endTransaction(tx, true); }
            session.save("Unaccepted release candidates", monitor);
            result.add("passes", passes);
            Files.writeString(Path.of(args[4]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
            println("Release candidate report complete");
        } finally {
            if (session != null) session.release(this);
            historical.close();
        }
    }
}
