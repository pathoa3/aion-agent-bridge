// Pass622 Ghidra Java exporter for native S2C receive/world-handshake path.
// Run inside Ghidra headless as a fallback when Jython scripting is unavailable.

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
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public class ghidra_export_s2c_receive_path extends GhidraScript {
    private static final String[] NETWORK_NAMES = new String[] {
        "recv", "WSARecv", "recvfrom", "send", "WSASend", "closesocket",
        "connect", "select", "ioctlsocket", "InternetReadFile", "ReadFile"
    };
    private static final String[] VM_ANCHORS = new String[] {
        "0x11B562BD", "0x11B5630F", "0x11B5932F", "0x11B57796",
        "0x11B55DF6", "0x11B54E6F", "0x11B566B4", "0x11B56C63"
    };
    private static final int MAX_DEPTH = 3;

    private FunctionManager fm;
    private DecompInterface decomp;

    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "C:\\AionTools\\aion_decoder_agent\\outbox\\pass622_ghidra_s2c_receive_exports";
        File outDir = new File(outPath);
        outDir.mkdirs();
        fm = currentProgram.getFunctionManager();
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        Map<String, Function> seeds = new LinkedHashMap<String, Function>();
        List<String> importRows = new ArrayList<String>();
        importRows.add("api,symbol_address,from_address,function,function_entry");

        for (String name : NETWORK_NAMES) {
            SymbolIterator syms = currentProgram.getSymbolTable().getSymbols(name);
            while (syms.hasNext()) {
                Symbol sym = syms.next();
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(sym.getAddress());
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Function fn = functionAtOrContaining(ref.getFromAddress());
                    String fnName = fn == null ? "" : fn.getName();
                    String fnEntry = fn == null ? "" : addrText(fn.getEntryPoint());
                    importRows.add(csv(name) + "," + csv(addrText(sym.getAddress())) + "," + csv(addrText(ref.getFromAddress())) + "," + csv(fnName) + "," + csv(fnEntry));
                    if (fn != null) seeds.put(fnEntry, fn);
                }
            }
        }

        for (String anchor : VM_ANCHORS) {
            try {
                Function fn = functionAtOrContaining(toAddr(anchor));
                if (fn != null) seeds.put(addrText(fn.getEntryPoint()), fn);
            } catch (Exception ignored) {}
        }

        Map<String, Integer> callers = walk(seeds, true);
        Map<String, Integer> callees = walk(seeds, false);
        Map<String, Function> targets = new LinkedHashMap<String, Function>();
        targets.putAll(seeds);
        for (String k : callers.keySet()) targets.put(k, functionAtOrContaining(toAddr(k)));
        for (String k : callees.keySet()) targets.put(k, functionAtOrContaining(toAddr(k)));

        List<String> functionRows = new ArrayList<String>();
        List<String> writeRows = new ArrayList<String>();
        List<String> edgeRows = new ArrayList<String>();
        functionRows.add("entry,name,seed,caller_depth,callee_depth,vm_anchor_hits,disasm_file,pcode_file,decomp_file");
        writeRows.add("function,function_entry,pattern,line");
        edgeRows.add("from_entry,from_name,to_entry,to_name");

        for (String key : targets.keySet()) {
            Function fn = targets.get(key);
            if (fn == null) continue;
            String base = key.replace("0x", "") + "_" + fn.getName().replaceAll("[^A-Za-z0-9_]", "_");
            String disasm = disasmText(fn);
            String pcode = pcodeText(fn);
            String decompText = decompileText(fn);
            writeFile(new File(outDir, base + ".disasm.txt"), disasm);
            writeFile(new File(outDir, base + ".pcode.txt"), pcode);
            writeFile(new File(outDir, base + ".decomp.txt"), decompText);
            functionRows.add(csv(key) + "," + csv(fn.getName()) + "," + csv(Boolean.toString(seeds.containsKey(key))) + "," + csv(depthText(callers, key)) + "," + csv(depthText(callees, key)) + "," + csv(anchorHits(fn, disasm)) + "," + csv(base + ".disasm.txt") + "," + csv(base + ".pcode.txt") + "," + csv(base + ".decomp.txt"));
            for (Function callee : calleesOf(fn)) edgeRows.add(csv(key) + "," + csv(fn.getName()) + "," + csv(addrText(callee.getEntryPoint())) + "," + csv(callee.getName()));
            for (String line : (pcode + "\n" + disasm).split("\n")) {
                String up = line.toUpperCase();
                if (up.contains("STORE") || Pattern.compile("\\bMOV\\s+\\w+ PTR \\[").matcher(up).find()) {
                    String pat = (up.contains("QWORD") || up.contains(":8") || up.contains("(8)")) ? "8-byte-write" : "write";
                    if (up.contains("INT_XOR") || up.contains("INT_ADD") || up.contains("INT_MULT")) pat += "+key-arithmetic-nearby";
                    writeRows.add(csv(fn.getName()) + "," + csv(key) + "," + csv(pat) + "," + csv(line.length() > 240 ? line.substring(0, 240) : line));
                }
            }
        }

        writeFile(new File(outDir, "import_refs.csv"), join(importRows));
        writeFile(new File(outDir, "candidate_functions.csv"), join(functionRows));
        writeFile(new File(outDir, "call_edges.csv"), join(edgeRows));
        writeFile(new File(outDir, "write_hints.csv"), join(writeRows));
        writeFile(new File(outDir, "export_manifest.txt"), "program=" + currentProgram.getName() + "\nmax_depth=" + MAX_DEPTH + "\nfunctions=" + (functionRows.size() - 1) + "\nwrites=" + (writeRows.size() - 1) + "\n");
        println("Pass622 Java S2C receive export wrote " + (functionRows.size() - 1) + " functions to " + outPath);
    }

    private String addrText(Address a) { return "0x" + a.toString().toUpperCase(); }
    private Function functionAtOrContaining(Address a) { Function f = fm.getFunctionAt(a); return f != null ? f : fm.getFunctionContaining(a); }
    private String depthText(Map<String, Integer> m, String k) { return m.containsKey(k) ? Integer.toString(m.get(k)) : ""; }
    private String csv(String s) { if (s == null) s = ""; return "\"" + s.replace("\"", "\"\"") + "\""; }
    private String join(List<String> rows) { StringBuilder sb = new StringBuilder(); for (String r: rows) sb.append(r).append("\n"); return sb.toString(); }
    private void writeFile(File f, String s) throws Exception { FileWriter w = new FileWriter(f); w.write(s == null ? "" : s); w.close(); }

    private Map<String, Integer> walk(Map<String, Function> seeds, boolean callerDirection) {
        Map<String, Integer> seen = new HashMap<String, Integer>();
        ArrayDeque<Object[]> q = new ArrayDeque<Object[]>();
        for (Function f : seeds.values()) q.add(new Object[] {f, 0});
        while (!q.isEmpty()) {
            Object[] item = q.removeFirst();
            Function fn = (Function)item[0];
            int depth = ((Integer)item[1]).intValue();
            String key = addrText(fn.getEntryPoint());
            if (seen.containsKey(key) && seen.get(key) <= depth) continue;
            seen.put(key, depth);
            if (depth >= MAX_DEPTH) continue;
            List<Function> next = callerDirection ? callersOf(fn) : calleesOf(fn);
            for (Function n : next) q.add(new Object[] {n, depth + 1});
        }
        return seen;
    }

    private List<Function> callersOf(Function fn) {
        List<Function> out = new ArrayList<Function>();
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(fn.getEntryPoint());
        while (refs.hasNext()) { Function f = functionAtOrContaining(refs.next().getFromAddress()); if (f != null) out.add(f); }
        return out;
    }
    private List<Function> calleesOf(Function fn) {
        List<Function> out = new ArrayList<Function>();
        InstructionIterator it = currentProgram.getListing().getInstructions(fn.getBody(), true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            for (Address a : ins.getFlows()) { Function f = functionAtOrContaining(a); if (f != null) out.add(f); }
        }
        return out;
    }
    private String disasmText(Function fn) {
        StringBuilder sb = new StringBuilder();
        InstructionIterator it = currentProgram.getListing().getInstructions(fn.getBody(), true);
        while (it.hasNext()) { Instruction ins = it.next(); sb.append(addrText(ins.getAddress())).append(" ").append(ins.toString()).append("\\n"); }
        return sb.toString();
    }
    private String pcodeText(Function fn) {
        StringBuilder sb = new StringBuilder();
        InstructionIterator it = currentProgram.getListing().getInstructions(fn.getBody(), true);
        while (it.hasNext()) { Instruction ins = it.next(); for (PcodeOp op : ins.getPcode()) sb.append(addrText(ins.getAddress())).append(" ").append(op.toString()).append("\\n"); }
        return sb.toString();
    }
    private String decompileText(Function fn) {
        try { DecompileResults r = decomp.decompileFunction(fn, 60, monitor); return r.decompileCompleted() ? r.getDecompiledFunction().getC() : ""; } catch (Exception e) { return "DECOMPILE_ERROR: " + e.toString(); }
    }
    private String anchorHits(Function fn, String disasm) {
        String up = (fn.getName() + " " + addrText(fn.getEntryPoint()) + " " + disasm).toUpperCase();
        List<String> hits = new ArrayList<String>();
        for (String a : VM_ANCHORS) if (up.contains(a.substring(2).toUpperCase())) hits.add(a);
        return String.join(";", hits);
    }
}


