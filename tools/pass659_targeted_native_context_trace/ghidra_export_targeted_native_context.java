// Pass659 targeted native context trace exporter. Raw output is local-only.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.io.File;
import java.io.FileWriter;
import java.util.*;

public class ghidra_export_targeted_native_context extends GhidraScript {
    private static final String[] SEEDS = new String[] {"0x11B56C63","0x11B50330","0x1195DA7B","0x11B52CE5","0x11B45846","0x11B5625B"};
    private static final String WAYPOINT = "0x11B57075";
    private FunctionManager fm;
    private DecompInterface decomp;
    private File outDir;

    public void run() throws Exception {
        String[] args = getScriptArgs();
        String out = args.length > 0 ? args[0] : "C:\\AionTools\\aion_decoder_agent\\outbox\\pass659_targeted_native_context_trace";
        outDir = new File(out); outDir.mkdirs();
        fm = currentProgram.getFunctionManager();
        decomp = new DecompInterface(); decomp.openProgram(currentProgram);
        LinkedHashMap<String,Function> targets = new LinkedHashMap<String,Function>();
        List<String> seedRows = new ArrayList<String>(); seedRows.add("seed_address,function_entry,function_name,resolved,role,error");
        for (String s: SEEDS) addSeed(s, "seed", targets, seedRows);
        addSeed(WAYPOINT, "control_flow_waypoint", targets, seedRows);
        LinkedHashMap<String,Integer> callerDepth = walk(targets.values(), true, 6);
        LinkedHashMap<String,Integer> calleeDepth = walk(targets.values(), false, 2);
        for (String k: callerDepth.keySet()) { Function f = fnAt(toAddr(k)); if (f != null) targets.put(k, f); }
        for (String k: calleeDepth.keySet()) { Function f = fnAt(toAddr(k)); if (f != null) targets.put(k, f); }
        List<String> fnRows = new ArrayList<String>(); fnRows.add("entry,name,is_seed,is_waypoint,caller_depth,callee_depth,param_summary,local_var_count");
        List<String> edgeRows = new ArrayList<String>(); edgeRows.add("from_entry,from_name,to_entry,to_name,callsite_address,evidence");
        List<String> refRows = new ArrayList<String>(); refRows.add("kind,from_entry,from_name,to_entry,to_name,from_address,to_address");
        List<String> storeRows = new ArrayList<String>(); storeRows.add("function_entry,function_name,op_address,space_input,dest_varnode,value_varnode,value_size,context_hint");
        List<String> callArgRows = new ArrayList<String>(); callArgRows.add("caller_entry,caller_name,callee_entry,callee_name,callsite_address,input_count,input_varnodes,windows_x64_hint");
        for (String key: targets.keySet()) {
            Function fn = targets.get(key); if (fn == null) continue;
            String base = key.replace("0x", "") + "_" + clean(fn.getName());
            String dis = disasm(fn); String pc = pcode(fn); DecompileResults dr = decompile(fn); String dc = decompText(dr); String hp = highPcodeText(dr);
            write(new File(outDir, base + ".disasm.txt"), dis);
            write(new File(outDir, base + ".pcode.txt"), pc);
            write(new File(outDir, base + ".decomp.txt"), dc);
            write(new File(outDir, base + ".highpcode.txt"), hp);
            fnRows.add(csv(key)+","+csv(fn.getName())+","+csv(Boolean.toString(isSeed(key)))+","+csv(Boolean.toString(key.equals(norm(WAYPOINT))))+","+csv(depth(callerDepth,key))+","+csv(depth(calleeDepth,key))+","+csv(params(fn))+","+csv(Integer.toString(fn.getLocalVariables().length)));
            exportEdges(fn, edgeRows, refRows, callArgRows);
            exportStores(fn, storeRows, dr);
        }
        write(new File(outDir,"seed_coverage.csv"), join(seedRows));
        write(new File(outDir,"target_functions.csv"), join(fnRows));
        write(new File(outDir,"call_edges.csv"), join(edgeRows));
        write(new File(outDir,"references.csv"), join(refRows));
        write(new File(outDir,"store_inputs.csv"), join(storeRows));
        write(new File(outDir,"callsite_arguments.csv"), join(callArgRows));
        write(new File(outDir,"export_manifest.json"), "{\n  \"program\": \"" + currentProgram.getName() + "\",\n  \"target_function_count\": " + (fnRows.size()-1) + ",\n  \"store_count\": " + (storeRows.size()-1) + ",\n  \"callsite_count\": " + (callArgRows.size()-1) + ",\n  \"note\": \"local-only raw high-pcode/decompile export\"\n}\n");
        println("Pass659 targeted native context export wrote " + (fnRows.size()-1) + " functions to " + out);
    }
    private void addSeed(String s, String role, LinkedHashMap<String,Function> targets, List<String> rows) {
        try { Function f = fnAt(toAddr(s)); if (f != null) { String k = addr(f.getEntryPoint()); targets.put(k,f); rows.add(csv(s)+","+csv(k)+","+csv(f.getName())+",true,"+csv(role)+","); } else rows.add(csv(s)+",,,false,"+csv(role)+",not_found"); } catch(Exception e) { rows.add(csv(s)+",,,false,"+csv(role)+","+csv(e.toString())); }
    }
    private LinkedHashMap<String,Integer> walk(Collection<Function> seeds, boolean callers, int maxDepth) {
        LinkedHashMap<String,Integer> seen = new LinkedHashMap<String,Integer>(); ArrayDeque<Object[]> q = new ArrayDeque<Object[]>();
        for (Function f: seeds) if (f != null) q.add(new Object[]{f,0});
        while(!q.isEmpty()) { Object[] it=q.removeFirst(); Function f=(Function)it[0]; int d=((Integer)it[1]).intValue(); String k=addr(f.getEntryPoint()); if(seen.containsKey(k) && seen.get(k)<=d) continue; seen.put(k,d); if(d>=maxDepth) continue; for(Function n: callers?callersOf(f):calleesOf(f)) q.add(new Object[]{n,d+1}); }
        return seen;
    }
    private Function fnAt(Address a) { Function f=fm.getFunctionAt(a); return f!=null?f:fm.getFunctionContaining(a); }
    private List<Function> callersOf(Function f) { ArrayList<Function> out=new ArrayList<Function>(); ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint()); while(it.hasNext()) { Function c=fnAt(it.next().getFromAddress()); if(c!=null) out.add(c); } return out; }
    private List<Function> calleesOf(Function f) { ArrayList<Function> out=new ArrayList<Function>(); InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(), true); while(it.hasNext()) { Instruction ins=it.next(); for(Address a: ins.getFlows()) { Function c=fnAt(a); if(c!=null) out.add(c); } } return out; }
    private void exportEdges(Function f,List<String> edges,List<String> refs,List<String> args) { InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(), true); while(it.hasNext()) { Instruction ins=it.next(); for(Address a: ins.getFlows()) { Function c=fnAt(a); if(c!=null) { edges.add(csv(addr(f.getEntryPoint()))+","+csv(f.getName())+","+csv(addr(c.getEntryPoint()))+","+csv(c.getName())+","+csv(addr(ins.getAddress()))+",flow"); PcodeOp[] ops=ins.getPcode(); for(PcodeOp op: ops) if(op.getOpcode()==PcodeOp.CALL || op.getOpcode()==PcodeOp.CALLIND) args.add(csv(addr(f.getEntryPoint()))+","+csv(f.getName())+","+csv(addr(c.getEntryPoint()))+","+csv(c.getName())+","+csv(addr(ins.getAddress()))+","+csv(Integer.toString(op.getNumInputs()))+","+csv(inputs(op))+","+csv("rcx,rdx,r8,r9 inferred by decompiler storage where available")); } } }
        ReferenceIterator ri=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint()); while(ri.hasNext()) { Reference r=ri.next(); Function src=fnAt(r.getFromAddress()); refs.add("to,"+csv(src==null?"":addr(src.getEntryPoint()))+","+csv(src==null?"":src.getName())+","+csv(addr(f.getEntryPoint()))+","+csv(f.getName())+","+csv(addr(r.getFromAddress()))+","+csv(addr(r.getToAddress()))); }
    }
    private void exportStores(Function f,List<String> rows,DecompileResults dr) { InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(), true); while(it.hasNext()) { Instruction ins=it.next(); for(PcodeOp op: ins.getPcode()) if(op.getOpcode()==PcodeOp.STORE) rows.add(csv(addr(f.getEntryPoint()))+","+csv(f.getName())+","+csv(addr(ins.getAddress()))+","+csv(vn(op.getInput(0)))+","+csv(vn(op.getInput(1)))+","+csv(vn(op.getInput(2)))+","+csv(op.getInput(2)==null?"":Integer.toString(op.getInput(2).getSize()))+","+csv(stackHint(op))); }
        try { HighFunction hf = dr == null ? null : dr.getHighFunction(); if(hf != null) { Iterator<PcodeOpAST> pit = hf.getPcodeOps(); while(pit.hasNext()) { PcodeOpAST op=pit.next(); if(op.getOpcode()==PcodeOp.STORE) rows.add(csv(addr(f.getEntryPoint()))+","+csv(f.getName())+","+csv(op.getSeqnum().getTarget().toString())+","+csv(vn(op.getInput(0)))+","+csv(vn(op.getInput(1)))+","+csv(vn(op.getInput(2)))+","+csv(op.getInput(2)==null?"":Integer.toString(op.getInput(2).getSize()))+","+csv("high_pcode_"+stackHint(op))); } } } catch(Exception e) {}
    }
    private String stackHint(PcodeOp op) { String s = inputs(op).toLowerCase(); return (s.contains("register,0x20") || s.contains("rsp") || s.contains("stack")) ? "stack_or_rsp_related" : "nonstack_or_unresolved"; }
    private String disasm(Function f) { StringBuilder sb=new StringBuilder(); InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(), true); while(it.hasNext()) { Instruction i=it.next(); sb.append(addr(i.getAddress())).append(" ").append(i.toString()).append("\n"); } return sb.toString(); }
    private String pcode(Function f) { StringBuilder sb=new StringBuilder(); InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(), true); while(it.hasNext()) { Instruction i=it.next(); for(PcodeOp op: i.getPcode()) sb.append(addr(i.getAddress())).append(" ").append(op.toString()).append("\n"); } return sb.toString(); }
    private DecompileResults decompile(Function f) { try { return decomp.decompileFunction(f, 60, monitor); } catch(Exception e) { return null; } }
    private String decompText(DecompileResults r) { try { return r!=null && r.decompileCompleted()?r.getDecompiledFunction().getC():""; } catch(Exception e) { return "DECOMPILE_ERROR: "+e.toString(); } }
    private String highPcodeText(DecompileResults r) { StringBuilder sb=new StringBuilder(); try { HighFunction hf=r==null?null:r.getHighFunction(); if(hf!=null) { Iterator<PcodeOpAST> it=hf.getPcodeOps(); while(it.hasNext()) sb.append(it.next().toString()).append("\n"); } } catch(Exception e) { sb.append("HIGHPCODE_ERROR: ").append(e.toString()).append("\n"); } return sb.toString(); }
    private String params(Function f) { StringBuilder sb=new StringBuilder(); for(Parameter p: f.getParameters()) sb.append(p.getName()).append(":").append(p.getDataType().getName()).append(":").append(p.getVariableStorage().toString()).append(";"); return sb.toString(); }
    private boolean isSeed(String k) { for(String s:SEEDS) if(norm(s).equals(k)) return true; return false; }
    private String norm(String s) { return "0x" + s.replace("0x","").replace("0X","").toUpperCase(); }
    private String addr(Address a) { return "0x"+a.toString().toUpperCase(); }
    private String vn(Varnode v) { return v==null?"":v.toString(); }
    private String inputs(PcodeOp op) { StringBuilder sb=new StringBuilder(); for(int i=0;i<op.getNumInputs();i++) sb.append(vn(op.getInput(i))).append("|"); return sb.toString(); }
    private String depth(Map<String,Integer> m,String k) { return m.containsKey(k)?Integer.toString(m.get(k)):""; }
    private String clean(String s) { return s.replaceAll("[^A-Za-z0-9_]","_"); }
    private String csv(String s) { if(s==null) s=""; return "\""+s.replace("\"","\"\"")+"\""; }
    private String join(List<String> xs) { StringBuilder sb=new StringBuilder(); for(String x:xs) sb.append(x).append("\n"); return sb.toString(); }
    private void write(File f,String s) throws Exception { FileWriter w=new FileWriter(f); w.write(s==null?"":s); w.close(); }
}
