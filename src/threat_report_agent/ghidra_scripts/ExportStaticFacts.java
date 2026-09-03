import com.google.gson.GsonBuilder;
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
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ExportStaticFacts extends GhidraScript {
    public void run() throws Exception {
        if (getScriptArgs().length != 1) {
            throw new IllegalArgumentException("Expected one JSON output path argument");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schema_version", "1.0");
        result.put("exporter", "ExportStaticFacts");
        List<Map<String, Object>> functions = new ArrayList<>();
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
        }
        result.put("functions", functions);
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
        try (FileWriter writer = new FileWriter(getScriptArgs()[0])) {
            new GsonBuilder().disableHtmlEscaping().create().toJson(result, writer);
        }
    }
}
