// Pass632 Java Ghidra exporter for targeted Path B xrefs/callers.
// Local-only output. Commit only summarized CSV/JSON artifacts.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ghidra_export_path_b_xrefs extends GhidraScript {
    private static final String[][] TARGETS = new String[][] {
        {"FUN_11b45846", "0x11B45846"},
        {"thunk_FUN_11b45846", "0x11B52CE5"},
        {"entry_or_thunk_1195D94A", "0x1195D94A"},
        {"FUN_11b56999", "0x11B56999"},
        {"FUN_11b59337", "0x11B59337"},
        {"FUN_11b59832", "0x11B59832"},
        {"FUN_11b59838", "0x11B59838"},
        {"FUN_11b566dd", "0x11B566DD"},
        {"dispatcher_FUN_11b5625b", "0x11B5625B"}
    };
    private static final String[] IMPORTS = new String[] {"recv", "WSARecv", "recvfrom", "send", "WSASend", "select", "ioctlsocket", "connect", "closesocket"};

    private FunctionManager fm;
    private DecompInterface decomp;

    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "C:\\AionTools\\aion_decoder_agent\\outbox\\pass631_path_b_xrefs";
        File outDir = new File(outPath);
        outDir.mkdirs();
        fm = currentProgram.getFunctionManager();
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        List<String> functionRows = new ArrayList<String>();
        List<String> xrefRows = new ArrayList<String>();
        List<String> edgeRows = new ArrayList<String>();
        List<String> importRows = new ArrayList<String>();
        functionRows.add("label,entry,name,address_requested");
        xrefRows.add("target,from_address,caller_entry,caller_name,ref_type");
        edgeRows.add("from_entry,from_name,to_entry,to_name");
        importRows.add("api,from_address,caller_entry,caller_name");

        Map<String, Function> seen = new LinkedHashMap<String, Function>();

        for (String[] target : TARGETS) {
            Address a = toAddr(target[1]);
            Function fn = functionAtOrContaining(a);
            collectXrefs(a, xrefRows, seen);
            if (fn != null) addFunction(target[0], target[1], fn, seen, functionRows, edgeRows, outDir);
        }

        ArrayList<Function> callerFns = new ArrayList<Function>(seen.values());
        for (Function fn : callerFns) {
            addCallersOf(fn, seen, functionRows, edgeRows, outDir);
        }

        for (String name : IMPORTS) {
            SymbolIterator syms = currentProgram.getSymbolTable().getSymbols(name);
            while (syms.hasNext()) {
                Symbol sym = syms.next();
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(sym.getAddress());
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Function fn = functionAtOrContaining(ref.getFromAddress());
                    importRows.add(csv(name) + "," + csv(addrText(ref.getFromAddress())) + "," + csv(fn == null ? "" : addrText(fn.getEntryPoint())) + "," + csv(fn == null ? "" : fn.getName()));
                }
            }
        }

        writeFile(new File(outDir, "path_b_functions.csv"), join(functionRows));
        writeFile(new File(outDir, "path_b_xrefs.csv"), join(xrefRows));
        writeFile(new File(outDir, "path_b_call_edges.csv"), join(edgeRows));
        writeFile(new File(outDir, "path_b_import_refs.csv"), join(importRows));
        writeFile(new File(outDir, "path_b_manifest.json"), "{\n  \"exporter\": \"java\",\n  \"explicit_no_callers\": false,\n  \"function_rows\": " + (functionRows.size() - 1) + ",\n  \"xref_rows\": " + (xrefRows.size() - 1) + "\n}\n");
        println("Pass632 Java Path B xref export wrote functions=" + (functionRows.size() - 1) + " xrefs=" + (xrefRows.size() - 1));
    }

    private String addrText(Address a) { return "0x" + a.toString().toUpperCase(); }
    private String csv(String s) { if (s == null) s = ""; return "\"" + s.replace("\"", "\"\"") + "\""; }
    private String join(List<String> rows) { StringBuilder sb = new StringBuilder(); for (String r : rows) sb.append(r).append("\n"); return sb.toString(); }
    private void writeFile(File f, String s) throws Exception { FileWriter w = new FileWriter(f); w.write(s == null ? "" : s); w.close(); }
    private Function functionAtOrContaining(Address a) { Function f = fm.getFunctionAt(a); return f != null ? f : fm.getFunctionContaining(a); }

    private void collectXrefs(Address target, List<String> rows, Map<String, Function> seen) {
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(target);
        while (refs.hasNext()) {
            Reference ref = refs.next();
            Function caller = functionAtOrContaining(ref.getFromAddress());
            rows.add(csv(addrText(target)) + "," + csv(addrText(ref.getFromAddress())) + "," + csv(caller == null ? "" : addrText(caller.getEntryPoint())) + "," + csv(caller == null ? "" : caller.getName()) + "," + csv(ref.getReferenceType().toString()));
            if (caller != null) seen.put(addrText(caller.getEntryPoint()), caller);
        }
    }

    private void addFunction(String label, String requested, Function fn, Map<String, Function> seen, List<String> functionRows, List<String> edgeRows, File outDir) throws Exception {
        String key = addrText(fn.getEntryPoint());
        if (!seen.containsKey(key)) seen.put(key, fn);
        functionRows.add(csv(label) + "," + csv(key) + "," + csv(fn.getName()) + "," + csv(requested));
        String base = key.replace("0x", "") + "_" + fn.getName().replaceAll("[^A-Za-z0-9_]", "_");
        writeFile(new File(outDir, base + ".disasm.txt"), disasmText(fn));
        writeFile(new File(outDir, base + ".pcode.txt"), pcodeText(fn));
        writeFile(new File(outDir, base + ".decomp.txt"), decompileText(fn));
        for (Function callee : calleesOf(fn)) edgeRows.add(csv(key) + "," + csv(fn.getName()) + "," + csv(addrText(callee.getEntryPoint())) + "," + csv(callee.getName()));
    }

    private void addCallersOf(Function fn, Map<String, Function> seen, List<String> functionRows, List<String> edgeRows, File outDir) throws Exception {
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(fn.getEntryPoint());
        while (refs.hasNext()) {
            Reference ref = refs.next();
            Function caller = functionAtOrContaining(ref.getFromAddress());
            if (caller == null) continue;
            String key = addrText(caller.getEntryPoint());
            if (!seen.containsKey(key)) addFunction("direct_caller", "", caller, seen, functionRows, edgeRows, outDir);
        }
    }

    private List<Function> calleesOf(Function fn) {
        List<Function> out = new ArrayList<Function>();
        InstructionIterator it = currentProgram.getListing().getInstructions(fn.getBody(), true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            for (Address a : ins.getFlows()) {
                Function f = functionAtOrContaining(a);
                if (f != null) out.add(f);
            }
        }
        return out;
    }

    private String disasmText(Function fn) {
        StringBuilder sb = new StringBuilder();
        InstructionIterator it = currentProgram.getListing().getInstructions(fn.getBody(), true);
        while (it.hasNext()) { Instruction ins = it.next(); sb.append(addrText(ins.getAddress())).append(" ").append(ins.toString()).append("\n"); }
        return sb.toString();
    }

    private String pcodeText(Function fn) {
        StringBuilder sb = new StringBuilder();
        InstructionIterator it = currentProgram.getListing().getInstructions(fn.getBody(), true);
        while (it.hasNext()) { Instruction ins = it.next(); for (PcodeOp op : ins.getPcode()) sb.append(addrText(ins.getAddress())).append(" ").append(op.toString()).append("\n"); }
        return sb.toString();
    }

    private String decompileText(Function fn) {
        try { DecompileResults r = decomp.decompileFunction(fn, 60, monitor); return r.decompileCompleted() ? r.getDecompiledFunction().getC() : ""; }
        catch (Exception e) { return "DECOMPILE_ERROR: " + e.toString(); }
    }
}
