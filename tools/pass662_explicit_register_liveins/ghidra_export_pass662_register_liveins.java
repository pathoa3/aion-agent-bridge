// Pass662 explicit Windows x64 register live-in exporter. Raw output is local-only.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import java.io.File;
import java.io.FileWriter;
import java.util.*;

public class ghidra_export_pass662_register_liveins extends GhidraScript {
    private static final String[] TARGETS = new String[] {"0x11B503FD","0x1195DA7B","0x11B50330","0x11B56C63"};
    private static final String[] REGS = new String[] {"RCX","RDX","R8","R9","RSI","RDI","RBP","R12","R13","R14","R15"};
    private static final String[] SITES = new String[] {"0x11B503FD","0x1195DA7B","0x11B50340","0x119BAEAB"};
    private FunctionManager fm;
    private DecompInterface decomp;
    private File outDir;

    public void run() throws Exception {
        String[] args = getScriptArgs();
        String out = args.length > 0 ? args[0] : "C:\\AionTools\\aion_decoder_agent\\outbox\\pass662_explicit_register_liveins";
        outDir = new File(out); outDir.mkdirs();
        fm = currentProgram.getFunctionManager();
        decomp = new DecompInterface(); decomp.openProgram(currentProgram);

        ArrayList<String> inv = new ArrayList<String>(); inv.add("register,found,address_space,offset,size_bytes,bit_length");
        ArrayList<String> proto = new ArrayList<String>(); proto.add("function_entry,function_name,signature,calling_convention,compiler_spec,default_calling_convention,param_count,return_type");
        ArrayList<String> inputs = new ArrayList<String>(); inputs.add("function_entry,function_name,register,register_found,matching_varnode_found,varnode,is_input,def_opcode,def_address,descendant_count,uses_summary,classification");
        ArrayList<String> defs = new ArrayList<String>(); defs.add("function_entry,register,callsite_address,nearest_def_before_site,def_opcode,def_address,reaching_status,varnode,notes");
        ArrayList<String> uses = new ArrayList<String>(); uses.add("function_entry,register,varnode,use_opcode,use_address,use_context,semantic_hint");
        ArrayList<String> thunk = new ArrayList<String>(); thunk.add("transition,caller_function,callee_function,callsite_address,register,passthrough_status,evidence");
        ArrayList<String> callsite = new ArrayList<String>(); callsite.add("transition,function_entry,callsite_address,register,register_found,matching_high_varnode_found,varnode,input_or_defined,reaching_definition,uses_at_or_after_site,semantic_hint,confidence");
        ArrayList<String> model = new ArrayList<String>(); model.add("function_entry,function_name,compiler_spec,prototype_model,prototype_status,parameter_storage_available,note");

        LinkedHashMap<String, RegInfo> regs = new LinkedHashMap<String, RegInfo>();
        for (String rn: REGS) {
            Register r = currentProgram.getRegister(rn);
            RegInfo info = new RegInfo(rn, r);
            regs.put(rn, info);
            inv.add(csv(rn)+","+csv(Boolean.toString(r != null))+","+csv(info.space)+","+csv(info.offset)+","+csv(Integer.toString(info.size))+","+csv(Integer.toString(info.bits)));
        }

        for (String ts: TARGETS) {
            Function fn = fnAt(toAddr(ts));
            if (fn == null) continue;
            DecompileResults dr = decomp.decompileFunction(fn, 60, monitor);
            HighFunction hf = null; try { hf = dr == null ? null : dr.getHighFunction(); } catch(Exception ignored) {}
            String fentry = addr(fn.getEntryPoint());
            String sig = ""; try { sig = fn.getSignature().toString(); } catch(Exception e) { sig = fn.getName(); }
            String cc = ""; try { cc = fn.getCallingConventionName(); } catch(Exception ignored) {}
            String cs = ""; try { cs = currentProgram.getCompilerSpec().getCompilerSpecID().toString(); } catch(Exception ignored) {}
            String dcc = ""; try { dcc = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(); } catch(Exception ignored) {}
            String ret = ""; try { ret = fn.getReturnType().getName(); } catch(Exception ignored) {}
            proto.add(csv(fentry)+","+csv(fn.getName())+","+csv(sig)+","+csv(cc)+","+csv(cs)+","+csv(dcc)+","+csv(Integer.toString(fn.getParameterCount()))+","+csv(ret));
            model.add(csv(fentry)+","+csv(fn.getName())+","+csv(cs)+","+csv(dcc)+","+csv(fn.getParameterCount()==0 ? "undefined_zero_parameter" : "parameters_present")+","+csv(Boolean.toString(fn.getParameterCount()>0))+","+csv("register live-ins recovered by explicit register matching, not call inputs"));
            Map<String, ArrayList<Varnode>> matched = collectRegisterVarnodes(hf, regs);
            for (String rn: REGS) {
                RegInfo ri = regs.get(rn);
                ArrayList<Varnode> vs = matched.get(rn);
                if (vs == null || vs.isEmpty()) {
                    inputs.add(csv(fentry)+","+csv(fn.getName())+","+csv(rn)+","+csv(Boolean.toString(ri.reg != null))+",false,,false,,,,0,,no_matching_highfunction_varnode");
                    continue;
                }
                HashSet<String> seen = new HashSet<String>();
                for (Varnode v: vs) {
                    String key = vn(v); if (seen.contains(key)) continue; seen.add(key);
                    String defop = ""; String defaddr = ""; try { PcodeOp d = v.getDef(); if (d != null) { defop = d.getMnemonic(); defaddr = "0x" + d.getSeqnum().getTarget().toString().toUpperCase(); } } catch(Exception ignored) {}
                    UseSummary us = summarizeUses(v, uses, fentry, rn);
                    inputs.add(csv(fentry)+","+csv(fn.getName())+","+csv(rn)+","+csv(Boolean.toString(ri.reg != null))+",true,"+csv(vn(v))+","+csv(Boolean.toString(v.isInput()))+","+csv(defop)+","+csv(defaddr)+","+us.count+","+csv(us.summary)+","+csv(classify(v, defop)));
                }
            }
            for (String site: SITES) {
                Address sa = toAddr(site); if (!fn.getBody().contains(sa)) continue;
                for (String rn: new String[] {"RCX","RDX","R8","R9"}) {
                    RegInfo ri = regs.get(rn); ArrayList<Varnode> vs = matched.get(rn);
                    Varnode chosen = (vs == null || vs.isEmpty()) ? null : vs.get(0);
                    String found = Boolean.toString(ri.reg != null); String hv = Boolean.toString(chosen != null);
                    String inputDef = "not_found"; String reaching = "no_matching_high_varnode"; String usesAfter = ""; String hint = "unresolved"; String conf = "none";
                    if (chosen != null) {
                        String defop = ""; String defaddr = ""; try { PcodeOp d = chosen.getDef(); if (d != null) { defop = d.getMnemonic(); defaddr = "0x"+d.getSeqnum().getTarget().toString().toUpperCase(); } } catch(Exception ignored) {}
                        inputDef = chosen.isInput() ? "function_input" : (defop.length()>0 ? defop+"@"+defaddr : "live_or_indirect");
                        reaching = reachingDefBefore(chosen, sa);
                        UseSummary us = summarizeDescendants(chosen);
                        usesAfter = us.summary;
                        hint = semantic(us.summary);
                        conf = chosen.isInput() || defop.length()>0 ? "medium" : "low";
                    }
                    String trans = transitionFor(fentry, site);
                    callsite.add(csv(trans)+","+csv(fentry)+","+csv(site)+","+csv(rn)+","+csv(found)+","+csv(hv)+","+csv(vn(chosen))+","+csv(inputDef)+","+csv(reaching)+","+csv(usesAfter)+","+csv(hint)+","+csv(conf));
                    defs.add(csv(fentry)+","+csv(rn)+","+csv(site)+","+csv(reaching)+","+csv(inputDef)+","+csv("")+","+csv(chosen==null?"unresolved_no_varnode":"resolved_or_livein")+","+csv(vn(chosen))+","+csv("explicit register matching; not CALL input list"));
                }
            }
        }
        // Thunk passthrough is storage-equivalence evidence only.
        for (String rn: new String[] {"RCX","RDX","R8","R9"}) {
            thunk.add("0x11B503FD->0x1195DA7B,0x11B503FD,0x1195DA7B,0x11B503FD,"+csv(rn)+",same_storage_live_through_if_present,"+csv("target and thunk have no params; explicit register rows determine presence"));
            thunk.add("0x1195DA7B->0x11B50330,0x1195DA7B,0x11B50330,0x1195DA7B,"+csv(rn)+",same_storage_live_through_if_present,"+csv("tail thunk/branch; explicit register rows determine presence"));
        }
        write(new File(outDir,"register_inventory.csv"), join(inv));
        write(new File(outDir,"function_input_registers.csv"), join(inputs));
        write(new File(outDir,"register_reaching_defs.csv"), join(defs));
        write(new File(outDir,"register_uses.csv"), join(uses));
        write(new File(outDir,"thunk_register_passthrough.csv"), join(thunk));
        write(new File(outDir,"callsite_liveins.csv"), join(callsite));
        write(new File(outDir,"prototype_model.csv"), join(model));
        write(new File(outDir,"target_function_prototypes.csv"), join(proto));
        write(new File(outDir,"export_manifest.json"), "{\n  \"target_count\": 4,\n  \"register_count\": 11,\n  \"note\": \"Pass662 explicit register live-in export, no call-input argument inference\"\n}\n");
        println("Pass662 explicit register live-in export wrote local outputs to " + outDir.getAbsolutePath());
    }
    private Map<String, ArrayList<Varnode>> collectRegisterVarnodes(HighFunction hf, LinkedHashMap<String, RegInfo> regs) {
        Map<String, ArrayList<Varnode>> out = new HashMap<String, ArrayList<Varnode>>();
        for (String rn: regs.keySet()) out.put(rn, new ArrayList<Varnode>());
        if (hf == null) return out;
        Iterator<PcodeOpAST> it = hf.getPcodeOps();
        while (it.hasNext()) {
            PcodeOpAST op = it.next();
            addIfRegister(op.getOutput(), regs, out);
            for (int i=0;i<op.getNumInputs();i++) addIfRegister(op.getInput(i), regs, out);
        }
        return out;
    }
    private void addIfRegister(Varnode v, LinkedHashMap<String, RegInfo> regs, Map<String, ArrayList<Varnode>> out) {
        if (v == null) return;
        for (String rn: regs.keySet()) if (regs.get(rn).matches(v)) out.get(rn).add(v);
    }
    private UseSummary summarizeUses(Varnode v, ArrayList<String> rows, String fentry, String rn) {
        UseSummary us = summarizeDescendants(v);
        try { Iterator<PcodeOp> it = v.getDescendants(); int c=0; while(it.hasNext()) { PcodeOp op=it.next(); if (c<40) rows.add(csv(fentry)+","+csv(rn)+","+csv(vn(v))+","+csv(op.getMnemonic())+","+csv("0x"+op.getSeqnum().getTarget().toString().toUpperCase())+","+csv(op.toString())+","+csv(semantic(op.getMnemonic()))); c++; } } catch(Exception ignored) {}
        return us;
    }
    private UseSummary summarizeDescendants(Varnode v) {
        int count=0; StringBuilder sb=new StringBuilder();
        try { Iterator<PcodeOp> it = v.getDescendants(); while(it.hasNext()) { PcodeOp op=it.next(); count++; if (count<=10) sb.append(op.getMnemonic()).append("@0x").append(op.getSeqnum().getTarget().toString().toUpperCase()).append(";"); } } catch(Exception ignored) {}
        return new UseSummary(count, sb.toString());
    }
    private String reachingDefBefore(Varnode v, Address site) {
        if (v == null) return "no_varnode";
        try { if (v.isInput()) return "function_input_live_in"; PcodeOp d = v.getDef(); if (d == null) return "no_def_live_or_unknown"; return d.getMnemonic()+"@0x"+d.getSeqnum().getTarget().toString().toUpperCase(); } catch(Exception e) { return "def_lookup_error"; }
    }
    private String transitionFor(String fentry, String site) {
        if (fentry.equals("0x11B503FD")) return "0x11B503FD->0x1195DA7B";
        if (fentry.equals("0x1195DA7B")) return "0x1195DA7B->0x11B50330";
        if (fentry.equals("0x11B50330")) return "0x11B50330->0x11B56C63";
        return fentry;
    }
    private String classify(Varnode v, String defop) { if (v == null) return "none"; try { if (v.isInput()) return "function_input_register_livein"; if (defop != null && defop.length()>0) return "defined_register_varnode"; } catch(Exception ignored) {} return "register_storage_unclassified"; }
    private String semantic(String uses) { String u = uses == null ? "" : uses.toUpperCase(); if (u.contains("LOAD") || u.contains("STORE")) return "object_or_context_use_candidate"; if (u.contains("PTR") || u.contains("INT_ADD")) return "pointer_arithmetic_candidate"; if (u.contains("CBRANCH") || u.contains("INT_EQUAL") || u.contains("INT_NOTEQUAL")) return "selector_or_branch_candidate"; if (u.length()==0) return "no_observed_use"; return "unrelated_or_passthrough"; }
    private Function fnAt(Address a) { Function f = fm.getFunctionAt(a); return f != null ? f : fm.getFunctionContaining(a); }
    private String addr(Address a) { return "0x"+a.toString().toUpperCase(); }
    private String vn(Varnode v) { return v == null ? "" : v.toString(); }
    private String csv(String s) { if (s == null) s=""; return "\""+s.replace("\"","\"\"").replace("\n"," ").replace("\r","")+"\""; }
    private String join(ArrayList<String> rows) { StringBuilder sb=new StringBuilder(); for(String r: rows) sb.append(r).append("\n"); return sb.toString(); }
    private void write(File f, String s) throws Exception { FileWriter w = new FileWriter(f); w.write(s == null ? "" : s); w.close(); }
    private class RegInfo {
        String name; Register reg; String space=""; String offset=""; int size=0; int bits=0;
        RegInfo(String n, Register r) { name=n; reg=r; if (r != null) { try { space = r.getAddressSpace().getName(); } catch(Exception ignored) {} try { offset = Long.toHexString(r.getOffset()); } catch(Exception ignored) {} try { size = r.getMinimumByteSize(); } catch(Exception ignored) {} try { bits = r.getBitLength(); } catch(Exception ignored) {} } }
        boolean matches(Varnode v) { if (reg == null || v == null) return false; try { if (!v.isRegister()) return false; long ro = reg.getOffset(); long vo = v.getOffset(); int rs = reg.getMinimumByteSize(); int vs = v.getSize(); return vo >= ro && vo < ro + Math.max(1, rs) && vs <= Math.max(16, rs); } catch(Exception e) { return false; } }
    }
    private class UseSummary { int count; String summary; UseSummary(int c, String s) { count=c; summary=s; } }
}
