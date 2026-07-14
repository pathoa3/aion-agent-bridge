// Pass661 minimal live-in argument resolver. Raw output is local-only.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import java.io.File;
import java.io.FileWriter;
import java.lang.reflect.Method;
import java.util.*;

public class ghidra_export_pass661_liveins extends GhidraScript {
    private static final String[] TARGETS = new String[] {"0x11B503FD","0x1195DA7B","0x11B50330","0x11B56C63"};
    private static final String[] CALLSITES = new String[] {"0x11B503FD","0x1195DA7B","0x11B50340","0x119BAEAB"};
    private FunctionManager fm;
    private DecompInterface decomp;
    private File outDir;
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String out = args.length > 0 ? args[0] : "C:\\AionTools\\aion_decoder_agent\\outbox\\pass661_livein_argument_resolution";
        outDir = new File(out); outDir.mkdirs();
        fm = currentProgram.getFunctionManager();
        decomp = new DecompInterface(); decomp.openProgram(currentProgram);
        ArrayList<String> proto = new ArrayList<String>(); proto.add("function_entry,function_name,prototype,calling_convention,thunk_target,param_count,return_type");
        ArrayList<String> params = new ArrayList<String>(); params.add("function_entry,param_index,param_name,datatype,size,variable_storage,first_storage_varnode,source");
        ArrayList<String> symbols = new ArrayList<String>(); symbols.add("function_entry,symbol_name,is_parameter,storage,high_variable,representative,datatype,category");
        ArrayList<String> ops = new ArrayList<String>(); ops.add("function_entry,seq_target,opcode,input_count,inputs,output,exact_callsite_match");
        ArrayList<String> live = new ArrayList<String>(); live.add("function_entry,callsite_address,opcode,input_index,varnode,varnode_class,def_opcode,descendant_count,uses_summary");
        for (String t: TARGETS) {
            Function fn = fnAt(toAddr(t));
            if (fn == null) continue;
            DecompileResults dr = decomp.decompileFunction(fn, 60, monitor);
            HighFunction hf = null;
            try { hf = dr == null ? null : dr.getHighFunction(); } catch (Exception ignored) {}
            String thunk = ""; try { Function th = fn.getThunkedFunction(true); if (th != null) thunk = addr(th.getEntryPoint()) + " " + th.getName(); } catch (Exception ignored) {}
            String prototype = ""; try { prototype = fn.getPrototypeString(false, false); } catch (Exception e) { prototype = fn.getSignature().toString(); }
            String cc = ""; try { cc = fn.getCallingConventionName(); } catch (Exception ignored) {}
            String ret = ""; try { ret = fn.getReturnType().getName(); } catch (Exception ignored) {}
            proto.add(csv(addr(fn.getEntryPoint()))+","+csv(fn.getName())+","+csv(prototype)+","+csv(cc)+","+csv(thunk)+","+csv(Integer.toString(fn.getParameterCount()))+","+csv(ret));
            int idx = 0;
            for (Parameter p: fn.getParameters()) {
                params.add(csv(addr(fn.getEntryPoint()))+","+idx+","+csv(p.getName())+","+csv(p.getDataType().getName())+","+csv(Integer.toString(p.getLength()))+","+csv(p.getVariableStorage().toString())+","+csv(p.getVariableStorage().getFirstVarnode()==null?"":p.getVariableStorage().getFirstVarnode().toString())+",Function.getParameters");
                idx++;
            }
            exportSymbols(addr(fn.getEntryPoint()), hf, symbols);
            exportOps(addr(fn.getEntryPoint()), hf, ops, live);
        }
        write(new File(outDir,"target_function_prototypes.csv"), join(proto));
        write(new File(outDir,"parameter_storage.csv"), join(params));
        write(new File(outDir,"high_symbols.csv"), join(symbols));
        write(new File(outDir,"high_pcode_ops.csv"), join(ops));
        write(new File(outDir,"livein_uses.csv"), join(live));
        write(new File(outDir,"export_manifest.json"), "{\n  \"target_count\": 4,\n  \"callsite_count\": 4,\n  \"note\": \"Pass661 local-only HighFunction prototype/live-in export\"\n}\n");
        println("Pass661 live-in export wrote local outputs to " + outDir.getAbsolutePath());
    }
    private void exportSymbols(String fentry, HighFunction hf, ArrayList<String> rows) {
        if (hf == null) return;
        try {
            Object map = hf.getLocalSymbolMap();
            Method getSymbols = map.getClass().getMethod("getSymbols");
            Iterator it = (Iterator)getSymbols.invoke(map);
            while (it.hasNext()) {
                Object sym = it.next();
                String name = call(sym,"getName");
                String isParam = call(sym,"isParameter");
                String storage = call(sym,"getStorage");
                Object hv = callObj(sym,"getHighVariable");
                String hvs = hv == null ? "" : hv.toString();
                String rep = ""; String dt = "";
                if (hv != null) { rep = call(hv,"getRepresentative"); dt = call(hv,"getDataType"); }
                String category = "local_symbol"; if ("true".equalsIgnoreCase(isParam)) category = "parameter_symbol"; if (storage.toLowerCase().contains("register")) category += ";register_storage"; if (storage.toLowerCase().contains("stack")) category += ";stack_storage";
                rows.add(csv(fentry)+","+csv(name)+","+csv(isParam)+","+csv(storage)+","+csv(hvs)+","+csv(rep)+","+csv(dt)+","+csv(category));
            }
        } catch (Exception e) { rows.add(csv(fentry)+",SYMBOL_EXPORT_ERROR,false,"+csv(e.toString())+",,,,error"); }
    }
    private void exportOps(String fentry, HighFunction hf, ArrayList<String> ops, ArrayList<String> live) {
        if (hf == null) return;
        try {
            Iterator<PcodeOpAST> it = hf.getPcodeOps();
            while (it.hasNext()) {
                PcodeOpAST op = it.next();
                String target = "0x" + op.getSeqnum().getTarget().toString().toUpperCase();
                String exact = isCallsite(target) ? "true" : "false";
                ops.add(csv(fentry)+","+csv(target)+","+csv(op.getMnemonic())+","+op.getNumInputs()+","+csv(inputs(op))+","+csv(vn(op.getOutput()))+","+csv(exact));
                if ("true".equals(exact) || op.getMnemonic().equals("CALL") || op.getMnemonic().equals("CALLIND") || op.getMnemonic().equals("BRANCH")) {
                    for (int i=0;i<op.getNumInputs();i++) {
                        Varnode v = op.getInput(i); String cls = classify(v); String def = "";
                        try { PcodeOp d = v == null ? null : v.getDef(); def = d == null ? "" : d.getMnemonic()+"@0x"+d.getSeqnum().getTarget().toString().toUpperCase(); } catch (Exception ignored) {}
                        int dc = 0; String uses = "";
                        try { Iterator<PcodeOp> dit = v.getDescendants(); StringBuilder sb = new StringBuilder(); while(dit.hasNext()) { PcodeOp u=dit.next(); dc++; if (dc <= 8) sb.append(u.getMnemonic()).append("@0x").append(u.getSeqnum().getTarget().toString().toUpperCase()).append(";"); } uses = sb.toString(); } catch(Exception ignored) {}
                        live.add(csv(fentry)+","+csv(target)+","+csv(op.getMnemonic())+","+i+","+csv(vn(v))+","+csv(cls)+","+csv(def)+","+dc+","+csv(uses));
                    }
                }
            }
        } catch (Exception e) { live.add(csv(fentry)+",EXPORT_ERROR,,,,"+csv(e.toString())+",,,"); }
    }
    private boolean isCallsite(String a) { for (String c: CALLSITES) if (norm(c).equals(a)) return true; return false; }
    private String classify(Varnode v) { if (v == null) return "none"; try { if (v.isConstant()) return "constant"; if (v.isRegister()) return v.isInput()?"register_live_in":"register"; if (v.isAddress()) return "global_or_address"; if (v.isUnique()) return v.isInput()?"unique_live_in":"unique_temp"; if (v.isInput()) return "function_input"; } catch(Exception ignored) {} return "indirect_unknown"; }
    private String inputs(PcodeOp op) { StringBuilder sb=new StringBuilder(); for(int i=0;i<op.getNumInputs();i++) sb.append(i).append(":").append(vn(op.getInput(i))).append("|"); return sb.toString(); }
    private String vn(Varnode v) { return v == null ? "" : v.toString(); }
    private Function fnAt(Address a) { Function f=fm.getFunctionAt(a); return f!=null?f:fm.getFunctionContaining(a); }
    private String addr(Address a) { return "0x"+a.toString().toUpperCase(); }
    private String norm(String s) { return "0x"+s.replace("0x","").replace("0X","").toUpperCase(); }
    private String call(Object o,String m) { try { Object r=o.getClass().getMethod(m).invoke(o); return r==null?"":r.toString(); } catch(Exception e) { return ""; } }
    private Object callObj(Object o,String m) { try { return o.getClass().getMethod(m).invoke(o); } catch(Exception e) { return null; } }
    private String csv(String s) { if(s==null) s=""; return "\""+s.replace("\"","\"\"").replace("\n"," ").replace("\r","")+"\""; }
    private String join(ArrayList<String> rows) { StringBuilder sb=new StringBuilder(); for(String r: rows) sb.append(r).append("\n"); return sb.toString(); }
    private void write(File f,String s) throws Exception { FileWriter w=new FileWriter(f); w.write(s==null?"":s); w.close(); }
}
