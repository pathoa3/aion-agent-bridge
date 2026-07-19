// Pass666 bounded Game Winsock IAT xref export.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class Pass666GameIatXrefs extends GhidraScript {
  private PrintWriter csv(File f) throws Exception { f.getParentFile().mkdirs(); return new PrintWriter(new OutputStreamWriter(new FileOutputStream(f), "UTF-8")); }
  private String q(Object o){ String s=String.valueOf(o==null?"":o); return "\""+s.replace("\"","\"\"")+"\""; }
  private void row(PrintWriter w, String kind, String slot, Address from, Instruction ins, Reference ref, String note){
    w.println(q(kind)+","+q(slot)+","+q(from)+","+q(ins==null?"":ins.toString())+","+q(ref==null?"":ref.getReferenceType())+","+q(note));
  }
  public void run() throws Exception {
    String[] args=getScriptArgs();
    File out=new File(args.length>0?args[0]:"C:/AionTools/aion_decoder_agent/outbox/pass666_recv_boundary");
    String slotsArg=args.length>1?args[1]:"";
    PrintWriter w=csv(new File(out,"game_iat_edges.csv"));
    w.println("edge_kind,target_slot_va,from_address,instruction,reference_type,note");
    Listing listing=currentProgram.getListing();
    ReferenceManager rm=currentProgram.getReferenceManager();
    AddressFactory af=currentProgram.getAddressFactory();
    Set<String> slots=new LinkedHashSet<String>();
    if(!slotsArg.trim().isEmpty()) for(String s: slotsArg.split(",")) slots.add(s.trim());
    for(String slot: slots){
      try{
        Address a=af.getAddress(slot);
        ReferenceIterator it=rm.getReferencesTo(a);
        int c=0;
        while(it.hasNext() && c<500){
          Reference r=it.next(); Address from=r.getFromAddress(); Instruction ins=listing.getInstructionAt(from);
          row(w,"xref_to_iat_slot",slot,from,ins,r,"direct Ghidra reference to supplied Game Winsock IAT slot"); c++;
        }
        if(c==0) row(w,"no_xref_to_iat_slot",slot,null,null,null,"no direct Ghidra reference to supplied slot");
      } catch(Exception e){ row(w,"slot_parse_error",slot,null,null,null,e.toString()); }
    }
    SymbolTable st=currentProgram.getSymbolTable();
    String[] names={"recv","WSARecv","recvfrom","WSARecvFrom","WSAIoctl","send","WSASend","connect"};
    for(String name:names){
      SymbolIterator syms=st.getSymbols(name);
      while(syms.hasNext()){
        Symbol sym=syms.next();
        ReferenceIterator it=rm.getReferencesTo(sym.getAddress()); int c=0;
        while(it.hasNext() && c<500){
          Reference r=it.next(); Address from=r.getFromAddress(); Instruction ins=listing.getInstructionAt(from);
          row(w,"xref_to_import_symbol",name,from,ins,r,"direct Ghidra reference to import/external symbol"); c++;
        }
      }
    }
    w.close();
    println("Pass666GameIatXrefs wrote game_iat_edges.csv");
  }
}
