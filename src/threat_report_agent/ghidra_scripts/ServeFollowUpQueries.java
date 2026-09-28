import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The RESIDENT follow-up service (plan §10.1: resident Ghidra provides only follow-up queries).
 *
 * `analyzeHeadless` runs this as its post-script; the script imports nothing itself and never executes the
 * sample - it answers questions about the program headless has already imported and analysed. It stays in
 * `accept()` for its whole external deadline, so the expensive import+auto-analysis happens ONCE and every
 * follow-up question after that is paid for on its own.
 *
 * Script arguments: <readyFile> <transcriptFile> <deadlineSeconds>
 *
 * Wire protocol: one JSON request per line, one JSON response per line.
 *   {"op":"ping"}                        -> {"resident":true,...}
 *   {"op":"query","entry":"140001000"}   -> {"op":"query","entry":"...","pseudo_c":{...},"error":null}
 *   {"op":"shutdown"}                    -> {"op":"shutdown","ok":true} then the script returns
 *
 * THE ENTRY IS THE IDENTITY KEY (plan §10.1/§10.2 C2). The lookup table is built from
 * `entryIdentity(function.getEntryPoint())`, so a re-ordered function iterator or a substituted symbol name
 * cannot move an answer onto a different function. Nothing here keys on index, symbol order or a fingerprint.
 *
 * A query for an entry this program does not contain answers `ENTRY_NOT_IN_PROGRAM` with `pseudo_c` ABSENT -
 * the caller must never be able to read a missing answer as an empty one.
 */
public class ServeFollowUpQueries extends GhidraScript {
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    public void run() throws Exception {
        if (getScriptArgs().length != 3) {
            throw new IllegalArgumentException("usage: <readyFile> <transcriptFile> <deadlineSeconds>");
        }
        String readyFile = getScriptArgs()[0];
        String transcriptFile = getScriptArgs()[1];
        long deadlineSeconds = Long.parseLong(getScriptArgs()[2]);
        long deadlineAt = System.currentTimeMillis() + (deadlineSeconds * 1000L);

        Map<String, Function> byIdentity = new LinkedHashMap<>();
        Map<String, String> identityToEntry = new LinkedHashMap<>();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            String identity = entryIdentity(function.getEntryPoint().toString());
            if (identity == null) {
                continue;
            }
            byIdentity.put(identity, function);
            identityToEntry.put(identity, function.getEntryPoint().toString());
        }

        ServerSocket server = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        try (FileWriter readyWriter = new FileWriter(readyFile);
             FileWriter transcriptWriter = new FileWriter(transcriptFile)) {
            readyWriter.write(Integer.toString(server.getLocalPort()));
            readyWriter.flush();
            boolean running = true;
            while (running && System.currentTimeMillis() < deadlineAt && !monitor.isCancelled()) {
                long remaining = deadlineAt - System.currentTimeMillis();
                if (remaining <= 0) {
                    break;
                }
                server.setSoTimeout((int) Math.max(1L, Math.min(remaining, 5000L)));
                Socket client = null;
                try {
                    client = server.accept();
                } catch (SocketTimeoutException idle) {
                    continue;
                }
                try (Socket connection = client;
                     BufferedReader reader = new BufferedReader(
                             new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8));
                     PrintWriter out = new PrintWriter(
                             new OutputStreamWriter(connection.getOutputStream(), StandardCharsets.UTF_8), true)) {
                    String line = reader.readLine();
                    JsonObject request = parseRequest(line);
                    JsonObject response = handle(request, byIdentity, identityToEntry, deadlineAt);
                    out.println(GSON.toJson(response));
                    transcriptWriter.write(GSON.toJson(request));
                    transcriptWriter.write("\t");
                    transcriptWriter.write(GSON.toJson(response));
                    transcriptWriter.write("\n");
                    transcriptWriter.flush();
                    running = !"shutdown".equals(stringField(request, "op"));
                }
            }
        } finally {
            server.close();
        }
    }

    private JsonObject handle(JsonObject request, Map<String, Function> byIdentity,
                              Map<String, String> identityToEntry, long deadlineAt) throws Exception {
        JsonObject response = new JsonObject();
        response.addProperty("schema_version", "1.0");
        String op = stringField(request, "op");
        response.addProperty("op", op == null ? "" : op);
        if (op == null) {
            response.addProperty("error", "MISSING_OP");
            return response;
        }
        if ("ping".equals(op)) {
            response.addProperty("resident", true);
            response.addProperty("program", currentProgram.getName());
            response.addProperty("function_count", byIdentity.size());
            return response;
        }
        if ("shutdown".equals(op)) {
            response.addProperty("ok", true);
            return response;
        }
        if (!"query".equals(op)) {
            response.addProperty("error", "UNSUPPORTED_OP");
            return response;
        }
        String requested = stringField(request, "entry");
        String identity = entryIdentity(requested);
        response.addProperty("requested_entry", requested == null ? "" : requested);
        response.addProperty("entry_identity", identity == null ? "" : identity);
        Function function = identity == null ? null : byIdentity.get(identity);
        if (function == null) {
            response.addProperty("entry", requested == null ? "" : requested);
            response.addProperty("error", "ENTRY_NOT_IN_PROGRAM");
            return response;
        }
        response.addProperty("entry", identityToEntry.get(identity));
        long started = System.currentTimeMillis();
        // The PER-QUERY decompile budget is DERIVED from the external deadline this script was launched with -
        // it is not a constant chosen here. A silent 120 s inside a service whose whole point is a bounded
        // external deadline is the un-sourced number plan §11.2 forbids, so the value actually used travels back
        // to the caller as `decompile_budget_seconds`.
        int budgetSeconds = (int) Math.max(1L,
                Math.min(Integer.MAX_VALUE, (deadlineAt - System.currentTimeMillis()) / 1000L));
        response.addProperty("decompile_budget_seconds", budgetSeconds);
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.toggleCCode(true);
            decompiler.openProgram(currentProgram);
            DecompileResults results = decompiler.decompileFunction(function, budgetSeconds, monitor);
            response.addProperty("decompile_millis", System.currentTimeMillis() - started);
            String pseudoC = (results != null && results.decompileCompleted()
                    && results.getDecompiledFunction() != null)
                            ? results.getDecompiledFunction().getC()
                            : null;
            if (pseudoC == null) {
                response.addProperty("error",
                        results == null ? "NULL_RESULTS" : String.valueOf(results.getErrorMessage()));
                return response;
            }
            JsonObject pseudo = new JsonObject();
            pseudo.addProperty("text", pseudoC);
            pseudo.addProperty("sha256", sha256(pseudoC));
            pseudo.addProperty("schema_version", "1.0");
            response.add("pseudo_c", pseudo);
        } finally {
            decompiler.dispose();
        }
        response.add("error", com.google.gson.JsonNull.INSTANCE);
        return response;
    }

    private static JsonObject parseRequest(String line) {
        if (line == null || line.trim().isEmpty()) {
            return new JsonObject();
        }
        try {
            JsonElement parsed = JsonParser.parseString(line);
            if (parsed != null && parsed.isJsonObject()) {
                return parsed.getAsJsonObject();
            }
        } catch (RuntimeException malformed) {
            // A malformed request is answered, not crashed on: the caller must see a reason, and one bad line
            // must not take the resident service down for every later query.
        }
        return new JsonObject();
    }

    private static String stringField(JsonObject request, String name) {
        JsonElement value = request.get(name);
        if (value == null || value.isJsonNull()) {
            return null;
        }
        return value.getAsString();
    }

    static String entryIdentity(String value) {
        if (value == null) {
            return null;
        }
        String cleaned = value.trim();
        if (cleaned.isEmpty()) {
            return null;
        }
        if (cleaned.regionMatches(true, 0, "0x", 0, 2)) {
            cleaned = cleaned.substring(2);
        }
        try {
            return new BigInteger(cleaned, 16).toString(16);
        } catch (NumberFormatException failure) {
            return null;
        }
    }

    private static String sha256(String value) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashed = digest.digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder builder = new StringBuilder();
        for (byte item : hashed) {
            builder.append(String.format("%02x", item));
        }
        return builder.toString();
    }
}
