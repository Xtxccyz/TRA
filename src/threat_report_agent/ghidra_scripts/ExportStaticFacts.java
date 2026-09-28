import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedStringIterator;
import java.io.FileWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * One-shot static export. This is the ONLY dump producer (plan §10.1: the headless export continues to produce
 * and freeze dump D; the resident service only answers follow-up queries).
 *
 * Script arguments:
 *   <outputPath>                                    legacy: export facts, no pseudo-C.
 *   <requestedEntries> <budgetSeconds> <outputPath>  additionally decompile the named entries.
 *
 * The requested-entry argument is a comma-separated list of entry values (with or without a 0x prefix), or "-"
 * for none. The output path is deliberately the LAST script argument so the command shape the Python adapter
 * builds stays append-only. The entry set is exactly what the caller asked for: there is no default set, no
 * `[:N]` cut and no "top functions" heuristic - an invented cap would make the dump silently partial.
 *
 * `<budgetSeconds>` is the PER-DECOMPILE budget and it is a CALLER argument, not a constant chosen here: the
 * Python adapter passes the run's own external deadline (`ToolPolicy.max_cpu_seconds`, policy version 1.0.0).
 * A silent 120 s inside a script whose whole point is a bounded external deadline is exactly the un-sourced
 * number the plan forbids. The value the script actually used is echoed into the output as
 * `decompile_budget_seconds`, so a reader can see it without reading this file.
 */
public class ExportStaticFacts extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1 && args.length != 3) {
            throw new IllegalArgumentException(
                    "Expected <outputPath> or <requestedEntries> <budgetSeconds> <outputPath>");
        }
        String requestedArgument = args.length == 3 ? args[0] : "";
        int decompileBudgetSeconds = args.length == 3 ? Integer.parseInt(args[1]) : 0;
        String outputPath = args[args.length - 1];
        Set<String> requestedIdentities = requestedEntryIdentities(requestedArgument);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schema_version", "1.0");
        result.put("exporter", "ExportStaticFacts");
        List<Map<String, Object>> functions = new ArrayList<>();
        // The requested entry set is resolved to the LIVE Function objects here, by `entry` identity - never by
        // position in the iteration - so decompilation cannot drift onto a different function when the function
        // or symbol order changes between two analyses (plan §10.2 C2).
        Map<String, Function> requestedFunctions = new LinkedHashMap<>();
        Map<String, Map<String, Object>> requestedItems = new LinkedHashMap<>();
        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext() && !monitor.isCancelled()) {
            Function function = iterator.next();
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", function.getName());
            item.put("entry", function.getEntryPoint().toString());
            item.put("entry_rva", function.getEntryPoint().subtract(currentProgram.getImageBase()));
            item.put("signature", function.getPrototypeString(false, false));
            List<String> mnemonics = new ArrayList<>();
            List<Map<String, Object>> instructionRows = new ArrayList<>();
            List<Map<String, Object>> pcodeRows = new ArrayList<>();
            List<Map<String, Object>> calls = new ArrayList<>();
            InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext() && mnemonics.size() < 10000) {
                Instruction instruction = instructions.next();
                mnemonics.add(instruction.getMnemonicString());
                Map<String, Object> instructionRow = new LinkedHashMap<>();
                instructionRow.put("address", instruction.getAddress().toString());
                instructionRow.put("mnemonic", instruction.getMnemonicString());
                instructionRow.put("text", instruction.toString());
                instructionRows.add(instructionRow);
                // Export a bounded native P-code view for mechanism recovery.
                // The Python adapter will fall back to instruction-derived
                // semantics when a processor does not expose P-code.
                if (pcodeRows.size() < 4096) {
                    for (PcodeOp op : instruction.getPcode()) {
                        if (pcodeRows.size() >= 4096) {
                            break;
                        }
                        Map<String, Object> pcode = new LinkedHashMap<>();
                        pcode.put("address", instruction.getAddress().toString());
                        pcode.put("opcode", op.getOpcode());
                        pcode.put("operation", op.getMnemonic());
                        Varnode output = op.getOutput();
                        pcode.put("output", output == null ? null : output.toString());
                        List<String> inputs = new ArrayList<>();
                        for (int inputIndex = 0; inputIndex < op.getNumInputs(); inputIndex++) {
                            Varnode input = op.getInput(inputIndex);
                            inputs.add(input == null ? "" : input.toString());
                        }
                        pcode.put("inputs", inputs);
                        pcodeRows.add(pcode);
                    }
                }
                for (Reference reference : instruction.getReferencesFrom()) {
                    Map<String, Object> call = new LinkedHashMap<>();
                    call.put("from", instruction.getAddress().toString());
                    call.put("to", reference.getToAddress().toString());
                    call.put("type", reference.getReferenceType().getName());
                    Symbol targetSymbol = getSymbolAt(reference.getToAddress());
                    if (targetSymbol != null) {
                        call.put("target_name", targetSymbol.getName());
                    }
                    Function targetFunction = getFunctionAt(reference.getToAddress());
                    if (targetFunction != null) {
                        call.put("target_function", targetFunction.getName());
                    }
                    calls.add(call);
                }
            }
            item.put("mnemonics", mnemonics);
            item.put("instructions", instructionRows);
            item.put("pcode_ops", pcodeRows);
            item.put("references_from", calls);
            List<Map<String, Object>> xrefs = new ArrayList<>();
            for (Reference reference : currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())) {
                Map<String, Object> xref = new LinkedHashMap<>();
                xref.put("from", reference.getFromAddress().toString());
                xref.put("to", reference.getToAddress().toString());
                xref.put("type", reference.getReferenceType().getName());
                xrefs.add(xref);
            }
            item.put("xrefs_to_entry", xrefs);
            List<Map<String, Object>> blocks = new ArrayList<>();
            CodeBlockIterator blockIterator = blockModel.getCodeBlocksContaining(function.getBody(), monitor);
            while (blockIterator.hasNext() && !monitor.isCancelled()) {
                CodeBlock block = blockIterator.next();
                Map<String, Object> blockItem = new LinkedHashMap<>();
                blockItem.put("start", block.getFirstStartAddress().toString());
                blockItem.put("end", block.getMaxAddress().toString());
                List<String> destinations = new ArrayList<>();
                CodeBlockReferenceIterator edgeIterator = block.getDestinations(monitor);
                while (edgeIterator.hasNext()) {
                    CodeBlockReference edge = edgeIterator.next();
                    destinations.add(edge.getDestinationAddress().toString());
                }
                blockItem.put("destinations", destinations);
                blocks.add(blockItem);
            }
            item.put("cfg_blocks", blocks);
            functions.add(item);
            String identity = entryIdentity(item.get("entry"));
            if (identity != null && requestedIdentities.contains(identity)) {
                requestedFunctions.put(identity, function);
                requestedItems.put(identity, item);
            }
        }
        // REAL DECOMPILATION, bounded to the caller's entry set. Nothing else in the product decompiles today
        // (P-6 recon F1), so this is where pseudo-C first exists at all. A decompile that fails is recorded as an
        // explicit `pseudo_c_error` on the function that failed - never as an absent field that a reader could
        // mistake for "not requested".
        List<String> decompiled = new ArrayList<>();
        List<String> requestedButAbsent = new ArrayList<>(requestedIdentities);
        if (!requestedIdentities.isEmpty() && !monitor.isCancelled()) {
            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.toggleCCode(true);
                decompiler.openProgram(currentProgram);
                for (String identity : requestedIdentities) {
                    Function function = requestedFunctions.get(identity);
                    Map<String, Object> item = requestedItems.get(identity);
                    if (function == null || item == null) {
                        continue;
                    }
                    requestedButAbsent.remove(identity);
                    long started = System.currentTimeMillis();
                    DecompileResults results = decompiler.decompileFunction(
                            function, decompileBudgetSeconds, monitor);
                    long millis = System.currentTimeMillis() - started;
                    String pseudoC = (results != null && results.decompileCompleted()
                            && results.getDecompiledFunction() != null)
                                    ? results.getDecompiledFunction().getC()
                                    : null;
                    item.put("decompile_millis", millis);
                    if (pseudoC == null) {
                        item.put("pseudo_c_error",
                                results == null ? "NULL_RESULTS" : String.valueOf(results.getErrorMessage()));
                    } else {
                        Map<String, Object> pseudo = new LinkedHashMap<>();
                        pseudo.put("text", pseudoC);
                        pseudo.put("sha256", sha256(pseudoC));
                        pseudo.put("schema_version", "1.0");
                        item.put("pseudo_c", pseudo);
                        decompiled.add(identity);
                    }
                }
            } finally {
                decompiler.dispose();
            }
        }
        result.put("functions", functions);
        result.put("requested_entries", new ArrayList<>(requestedIdentities));
        result.put("decompiled_entries", decompiled);
        result.put("requested_entries_absent", requestedButAbsent);
        result.put("decompile_budget_seconds", decompileBudgetSeconds);
        result.put("decompile_budget_source",
                decompileBudgetSeconds == 0
                        ? "no pseudo-C was requested, so no decompile budget applied"
                        : "the caller's <budgetSeconds> argument, which the Python adapter takes from the tool "
                                + "run's own external deadline (ToolPolicy.max_cpu_seconds, policy version 1.0.0)");
        // Export defined strings with their virtual addresses.  The Python
        // recovery pass uses this table to resolve GetProcAddress's RDX/EDX
        // procedure-name argument; raw string evidence remains separately
        // available through the intake/static parser.
        List<Map<String, Object>> strings = new ArrayList<>();
        DefinedStringIterator stringIterator = DefinedStringIterator.forProgram(currentProgram);
        while (stringIterator.hasNext() && !monitor.isCancelled() && strings.size() < 20000) {
            ghidra.program.model.listing.Data data = stringIterator.next();
            StringDataInstance instance = StringDataInstance.getStringDataInstance(data);
            String value = instance.getStringValue();
            if (value == null || value.trim().isEmpty()) {
                continue;
            }
            Map<String, Object> stringItem = new LinkedHashMap<>();
            stringItem.put("address", data.getAddress().toString());
            stringItem.put("text", value);
            stringItem.put("encoding", instance.getCharsetName());
            strings.add(stringItem);
        }
        result.put("strings", strings);
        List<Map<String, Object>> symbols = new ArrayList<>();
        SymbolIterator symbolsIterator = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbolsIterator.hasNext() && !monitor.isCancelled()) {
            Symbol symbol = symbolsIterator.next();
            if (symbol.isExternal() || symbol.isGlobal()) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("name", symbol.getName());
                item.put("address", symbol.getAddress().toString());
                item.put("type", symbol.getSymbolType().toString());
                item.put("external", symbol.isExternal());
                symbols.add(item);
            }
        }
        result.put("symbols", symbols);
        result.put("image_base", currentProgram.getImageBase().toString());
        try (FileWriter writer = new FileWriter(outputPath)) {
            new GsonBuilder().disableHtmlEscaping().create().toJson(result, writer);
        }
    }

    /**
     * The identity of a function, for BOTH sides of the comparison (plan §10.1: the identity key is `entry`).
     *
     * Ghidra prints an address padded to the address space (`00401000` on a 32-bit program, `140001000` on a
     * 64-bit one), while a caller may write `0x401000`. Lower-cased hex without a prefix and without leading
     * zeros is the one form both sides can agree on; the raw `entry` string is still exported unchanged, so no
     * reader loses the address as Ghidra wrote it.
     */
    private static String entryIdentity(Object value) {
        if (value == null) {
            return null;
        }
        String cleaned = String.valueOf(value).trim();
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

    private static Set<String> requestedEntryIdentities(String argument) {
        Set<String> identities = new LinkedHashSet<>();
        if (argument == null) {
            return identities;
        }
        for (String token : argument.split(",")) {
            String identity = entryIdentity(token);
            if (identity != null) {
                identities.add(identity);
            }
        }
        return identities;
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
