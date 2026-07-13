// Ghidra Java script: export recv/import wrapper xrefs for Pass635.
// Run under analyzeHeadless with output directory as the first script argument.
// Writes CSV summaries and per-function exports for static review only.
// IMPORTANT: saved as UTF-8 WITHOUT BOM so Ghidra headless compiler accepts it.

import java.io.*;
import java.util.*;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;

public class export_recv_import_wrappers extends GhidraScript {
    private static final String[] IMPORT_NAMES = new String[] {
        "recv", "WSARecv", "recvfrom", "WSASend", "send", "select", "ioctlsocket", "connect", "closesocket"
    };

    private File outDir;
    private DecompInterface decomp;

    public void run() throws Exception {
        String[] args = getScriptArgs();
        outDir = new File(args.length > 0 ? args[0] : "C:\\AionTools\\aion_decoder_agent\\outbox\\pass635_recv_wrappers");
        outDir.mkdirs();
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        PrintWriter imports = writer("recv_import_symbols.csv");
        imports.println("api,symbol_address,external,namespace");
        PrintWriter refs = writer("recv_import_xrefs.csv");
        refs.println("api,import_address,from_address,caller_entry,caller_name,ref_type");
        PrintWriter edges = writer("recv_wrapper_edges.csv");
        edges.println("from_entry,from_name,to_entry,to_name,edge_type");

        FunctionManager fm = currentProgram.getFunctionManager();
        Set<Function> toExport = new LinkedHashSet<Function>();
        for (String api : IMPORT_NAMES) {
            SymbolIterator syms = currentProgram.getSymbolTable().getSymbols(api);
            while (syms.hasNext() && !monitor.isCancelled()) {
                Symbol sym = syms.next();
                Address addr = sym.getAddress();
                imports.printf("\"%s\",\"%s\",\"%s\",\"%s\"%n", api, addr, sym.isExternal(), sym.getParentNamespace());
                ReferenceIterator riter = currentProgram.getReferenceManager().getReferencesTo(addr);
                while (riter.hasNext() && !monitor.isCancelled()) {
                    Reference ref = riter.next();
                    Address from = ref.getFromAddress();
                    Function caller = fm.getFunctionContaining(from);
                    String ce = caller == null ? "" : caller.getEntryPoint().toString();
                    String cn = caller == null ? "" : caller.getName();
                    refs.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n", api, addr, from, ce, cn, ref.getReferenceType());
                    if (caller != null) {
                        toExport.add(caller);
                        for (Function c : caller.getCalledFunctions(monitor)) {
                            edges.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"CALL\"%n", caller.getEntryPoint(), caller.getName(), c.getEntryPoint(), c.getName());
                            toExport.add(c);
                        }
                        for (Function p : caller.getCallingFunctions(monitor)) {
                            edges.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"CALLER\"%n", p.getEntryPoint(), p.getName(), caller.getEntryPoint(), caller.getName());
                            toExport.add(p);
                        }
                    }
                }
            }
        }
        imports.close();
        refs.close();
        edges.close();

        PrintWriter funcs = writer("recv_wrapper_functions.csv");
        funcs.println("entry,name,exported");
        for (Function f : toExport) {
            funcs.printf("\"%s\",\"%s\",\"true\"%n", f.getEntryPoint(), f.getName());
            exportFunction(f);
        }
        funcs.close();
        decomp.dispose();
    }

    private PrintWriter writer(String name) throws Exception {
        return new PrintWriter(new OutputStreamWriter(new FileOutputStream(new File(outDir, name)), "UTF-8"));
    }

    private String safeName(Function f) {
        return f.getEntryPoint().toString().replace(":", "_") + "_" + f.getName().replaceAll("[^A-Za-z0-9_.$-]", "_");
    }

    private void exportFunction(Function f) throws Exception {
        String base = safeName(f);
        PrintWriter dis = writer(base + ".disasm.txt");
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            dis.println(ins.getAddress() + " " + ins.toString());
        }
        dis.close();

        PrintWriter pc = writer(base + ".pcode.txt");
        it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            for (PcodeOp op : ins.getPcode()) {
                pc.println(ins.getAddress() + " " + op.toString());
            }
        }
        pc.close();

        PrintWriter dc = writer(base + ".decomp.txt");
        DecompileResults res = decomp.decompileFunction(f, 30, monitor);
        if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
            dc.println(res.getDecompiledFunction().getC());
        }
        dc.close();
    }
}
