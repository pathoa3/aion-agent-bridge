// Pass666 bounded CrySystem CreateSystemInterface/CreateGame edge export.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class Pass666CrySystemExport extends GhidraScript {
  private PrintWriter csv(File f) throws Exception { f.getParentFile().mkdirs(); return new PrintWriter(new OutputStreamWriter(new FileOutputStream(f), "UTF-8")); }
  private String q(Object o){ String s=String.valueOf(o==null?"":o); return "\""+s.replace("\"","\"\"")+"\""; }
  private void row(PrintWriter w, String kind, String name, Address addr, Address from, Instruction ins, String note){
    w.println(q(kind)+","+q(name)+","+q(addr)+","+q(from)+","+q(ins==null?"":ins.toString())+","+q(note));
  }
  public void run() throws Exception {
    String[] args=getScriptArgs();
    File out=new File(args.length>0?args[0]:"C:/AionTools/aion_decoder_agent/outbox/pass666_recv_boundary");
    PrintWriter w=csv(new File(out,"crysystem_edges.csv"));
    w.println("edge_kind,symbol,address,from_address,instruction,note");
    Listing listing=currentProgram.getListing();
    SymbolTable st=currentProgram.getSymbolTable();
    ReferenceManager rm=currentProgram.getReferenceManager();
    String[] targets={"CreateSystemInterface","CreateGame","AegInitEngine","GetProcAddress","LoadLibraryA","LoadLibraryW","LoadLibraryExA","LoadLibraryExW"};
    for(String name:targets){
      SymbolIterator syms=st.getSymbols(name); boolean any=false;
      while(syms.hasNext()){
        Symbol sym=syms.next(); any=true; Address a=sym.getAddress(); row(w,"symbol",name,a,null,null,"symbol present");
        ReferenceIterator refs=rm.getReferencesTo(a); int c=0;
        while(refs.hasNext() && c<500){
          Reference r=refs.next(); Address from=r.getFromAddress(); Instruction ins=listing.getInstructionAt(from);
          row(w,"xref_to_symbol",name,a,from,ins,"reference to symbol"); c++;
        }
        Function f=getFunctionAt(a);
        if(f==null) f=getFunctionContaining(a);
        if(f!=null){
          int n=0;
          InstructionIterator ii=listing.getInstructions(f.getBody(), true);
          while(ii.hasNext() && n<300){
            Instruction ins=ii.next(); String s=ins.toString().toLowerCase();
            if(s.contains("call") || s.contains("jmp") || s.contains("mov") || s.contains("lea"))
              row(w,"function_instruction",name,a,ins.getAddress(),ins,"bounded instruction from containing function");
            n++;
          }
        }
      }
      if(!any) row(w,"symbol_absent",name,null,null,null,"symbol absent in current Ghidra program");
    }
    w.close();
    println("Pass666CrySystemExport wrote crysystem_edges.csv");
  }
}
