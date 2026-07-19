from __future__ import annotations
import csv, hashlib, json, os, re, struct, subprocess, sys, time
from pathlib import Path

REPO=Path(r"C:\AionTools\AION_GITHUB_SYNC_REPO")
DEC=Path(r"C:\AionTools\aion_decoder_agent")
TOOL=REPO/'tools'/'pass666_recv_boundary'
OUT=DEC/'outbox'/'pass666_recv_boundary'
EURO=Path(r"C:\Program Files (x86)\EuroAion\bin64")
GH=Path(r"C:\Users\patho\Downloads\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat")
PROJ=Path(r"C:\AionTools\euroaion")
PROJNAME='euroaion'
KNOWN_GAME_SHA='c4b5ad116928685c0cd443bdb301e9fe04655d1129e9f9acad8254f68cc1846d'
TARGET_FUNCS={'recv','WSARecv','recvfrom','WSARecvFrom','WSAIoctl','AcceptEx','ConnectEx','DisconnectEx','send','WSASend','connect'}

def hx(x:int)->str: return f"0x{x:X}"
def now(): return time.strftime('%Y-%m-%dT%H:%M:%S%z')
def sha256(p:Path)->str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for c in iter(lambda:f.read(1<<20),b''): h.update(c)
    return h.hexdigest()
def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u64(b,o): return struct.unpack_from('<Q',b,o)[0]
def write_csv(path, rows, fields):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore'); w.writeheader(); w.writerows(rows)
def write_json(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(obj,indent=2,sort_keys=True),encoding='utf-8')

class PE:
    def __init__(self,path:Path, base_override=None):
        self.path=path; self.data=path.read_bytes(); self.base_override=base_override
        self.is_pe=False; self.is64=False; self.image_base=0; self.size_of_image=0; self.sections=[]; self.dirs=[]; self.imports=[]; self.exports=[]
        self.parse()
    def parse(self):
        b=self.data
        if len(b)<0x100 or b[:2]!=b'MZ': return
        pe=u32(b,0x3c)
        if pe+0x18>=len(b) or b[pe:pe+4]!=b'PE\0\0': return
        self.is_pe=True; ns=u16(b,pe+6); so=u16(b,pe+20); opt=pe+24; mag=u16(b,opt); self.is64=(mag==0x20b)
        parsed_base=u64(b,opt+24) if self.is64 else u32(b,opt+28)
        self.image_base=self.base_override if self.base_override is not None else parsed_base
        self.size_of_image=u32(b,opt+56); dd=opt+(112 if self.is64 else 96)
        self.dirs=[(u32(b,dd+i*8),u32(b,dd+i*8+4)) if dd+i*8+8<=len(b) else (0,0) for i in range(16)]
        off=opt+so
        for i in range(ns):
            s=off+i*40
            if s+40>len(b): break
            name=b[s:s+8].split(b'\0',1)[0].decode('ascii','replace')
            self.sections.append({'name':name,'va':u32(b,s+12),'vsize':u32(b,s+8),'raw_ptr':u32(b,s+20),'raw_size':u32(b,s+16),'chars':u32(b,s+36)})
        self.imports=self.impdir(1,'import')+self.impdir(13,'delay_import')
        self.exports=self.expdir()
    def r2o(self,rva):
        for s in self.sections:
            va=s['va']; span=max(s['vsize'],s['raw_size'])
            if va<=rva<va+span:
                # mapped image candidates have raw_ptr==va-ish or raw_ptr==file raw offset; accept both by bounds
                o=s['raw_ptr']+(rva-va)
                if 0<=o<len(self.data): return o
                if 0<=rva<len(self.data): return rva
                return None
        return rva if 0<=rva<len(self.data) else None
    def cstr(self,rva):
        o=self.r2o(rva)
        if o is None: return ''
        e=self.data.find(b'\0',o,min(len(self.data),o+4096))
        if e<0: e=min(len(self.data),o+4096)
        return self.data[o:e].decode('ascii','replace')
    def impdir(self,idx,kind):
        if idx>=len(self.dirs): return []
        rva,sz=self.dirs[idx]; o=self.r2o(rva)
        if not rva or o is None: return []
        rows=[]; delay=(idx==13); ds=32 if delay else 20; width=8 if self.is64 else 4; flag=0x8000000000000000 if self.is64 else 0x80000000
        for i in range(4096):
            d=o+i*ds
            if d+ds>len(self.data): break
            if delay:
                name_rva=u32(self.data,d+4); int_rva=u32(self.data,d+12); iat_rva=u32(self.data,d+16)
                if name_rva==int_rva==iat_rva==0: break
            else:
                int_rva=u32(self.data,d); name_rva=u32(self.data,d+12); iat_rva=u32(self.data,d+16)
                if int_rva==name_rva==iat_rva==0: break
            dll=self.cstr(name_rva)
            to=self.r2o(int_rva or iat_rva)
            if not dll or to is None: continue
            for n in range(8192):
                q=to+n*width
                if q+width>len(self.data): break
                val=u64(self.data,q) if self.is64 else u32(self.data,q)
                if not val: break
                if val&flag:
                    name=f'ordinal_{val&0xffff}'; ordv=str(val&0xffff)
                else:
                    ho=self.r2o(val); name=self.cstr(val+2) if ho is not None else ''; ordv=''
                slot=iat_rva+n*width
                rows.append({'dll':dll,'function':name,'ordinal':ordv,'kind':kind,'iat_slot_rva':hx(slot),'iat_slot_va':hx(self.image_base+slot)})
        return rows
    def expdir(self):
        if not self.dirs: return []
        rva,sz=self.dirs[0]; o=self.r2o(rva)
        if not rva or o is None or o+40>len(self.data): return []
        base=u32(self.data,o+16); nf=u32(self.data,o+20); nn=u32(self.data,o+24); fr=u32(self.data,o+28); nr=u32(self.data,o+32); orr=u32(self.data,o+36)
        fo=self.r2o(fr); no=self.r2o(nr); oo=self.r2o(orr); names={}
        if no is not None and oo is not None:
            for i in range(min(nn,100000)):
                if no+i*4+4>len(self.data) or oo+i*2+2>len(self.data): break
                names[u16(self.data,oo+i*2)]=self.cstr(u32(self.data,no+i*4))
        rows=[]
        if fo is None: return rows
        for i in range(min(nf,100000)):
            if fo+i*4+4>len(self.data): break
            rv=u32(self.data,fo+i*4)
            if rv: rows.append({'ordinal':base+i,'name':names.get(i,''),'rva':hx(rv),'va':hx(self.image_base+rv)})
        return rows

def mapped_candidates():
    paths=[]
    explicit=DEC/'game_unpacked_background'/'game_mapped.bin'
    if explicit.exists(): paths.append(explicit)
    for p in (DEC/'outbox').rglob('*'):
        if p.is_file() and p.name.lower() in {'mapped_game_baseline.bin','mapped_baseline.bin','game_mapped.bin'}:
            paths.append(p)
    # stable newest first, unique
    seen=set(); out=[]
    for p in sorted(paths, key=lambda x: x.stat().st_mtime, reverse=True):
        if str(p).lower() not in seen:
            out.append(p); seen.add(str(p).lower())
    return out

def validate_candidates():
    rows=[]; best=None; best_score=-1
    for p in mapped_candidates():
        try:
            pe=PE(p,0x10000000)
            targets=[i for i in pe.imports if i['function'] in TARGET_FUNCS or i['dll'].lower().startswith('ws2_32')]
            sec=';'.join(f"{s['name']}@{hx(s['va'])}+{hx(s['vsize'])}" for s in pe.sections)
            digest=sha256(p); score=(50 if pe.is_pe else 0)+(10 if pe.is64 else 0)+len(targets)
            rows.append({'path':str(p),'sha256':digest,'size':p.stat().st_size,'is_pe':pe.is_pe,'is64':pe.is64,'image_base':hx(pe.image_base) if pe.is_pe else '','size_of_image':hx(pe.size_of_image) if pe.is_pe else '','sections':sec,'import_count':len(pe.imports),'winsock_target_import_count':len(targets),'score':score})
            if score>best_score:
                best=(p,pe,digest,targets); best_score=score
        except Exception as e:
            rows.append({'path':str(p),'sha256':'','size':p.stat().st_size if p.exists() else 0,'is_pe':False,'is64':False,'image_base':'','size_of_image':'','sections':'','import_count':0,'winsock_target_import_count':0,'score':-1,'error':repr(e)})
    write_csv(OUT/'mapped_game_candidates.csv',rows,['path','sha256','size','is_pe','is64','image_base','size_of_image','sections','import_count','winsock_target_import_count','score','error'])
    return best,rows

def run_ghidra(program, script, extra_args):
    if not GH.exists(): return {'program':program,'exit_code':-1,'stdout':'','stderr':'analyzeHeadless missing'}
    cmd=[str(GH),str(PROJ),PROJNAME,'-process',program,'-noanalysis','-readOnly','-scriptPath',str(TOOL),'-postScript',script,*extra_args]
    started=time.time()
    cp=subprocess.run(cmd,cwd=str(REPO),capture_output=True,text=True,timeout=900)
    stem=Path(program).stem.lower()+'_'+Path(script).stem
    (OUT/(stem+'_stdout.log')).write_text(cp.stdout or '',encoding='utf-8')
    (OUT/(stem+'_stderr.log')).write_text(cp.stderr or '',encoding='utf-8')
    return {'program':program,'script':script,'command':cmd,'exit_code':cp.returncode,'elapsed_seconds':round(time.time()-started,3),'stdout_log':str(OUT/(stem+'_stdout.log')),'stderr_log':str(OUT/(stem+'_stderr.log'))}


def run_ghidra_import(binary_path, script, extra_args):
    if not GH.exists(): return {'program':str(binary_path),'exit_code':-1,'stdout':'','stderr':'analyzeHeadless missing'}
    tmp_proj=OUT/'ghidra_tmp_crysystem_project'
    tmp_name='pass666_crysystem'
    cmd=[str(GH),str(tmp_proj),tmp_name,'-import',str(binary_path),'-readOnly','-scriptPath',str(TOOL),'-postScript',script,*extra_args]
    started=time.time()
    cp=subprocess.run(cmd,cwd=str(REPO),capture_output=True,text=True,timeout=900)
    stem=Path(binary_path).stem.lower()+'_'+Path(script).stem+'_import'
    (OUT/(stem+'_stdout.log')).write_text(cp.stdout or '',encoding='utf-8')
    (OUT/(stem+'_stderr.log')).write_text(cp.stderr or '',encoding='utf-8')
    return {'program':str(binary_path),'script':script,'command':cmd,'exit_code':cp.returncode,'elapsed_seconds':round(time.time()-started,3),'stdout_log':str(OUT/(stem+'_stdout.log')),'stderr_log':str(OUT/(stem+'_stderr.log'))}
def classify_edges(edge_rows):
    out=[]
    for r in edge_rows:
        text=' '.join(str(r.get(k,'')) for k in r).lower()
        cls='unrelated'; reason='no recv/security/import edge semantics proven'
        if 'getprocaddress' in text or 'loadlibrary' in text:
            cls='dynamic resolution'; reason='references loader/proc-address API'
        if any(x.lower() in text for x in ['aeginit','secureengine','createsysteminterface','creategame']):
            cls='security/bootstrap initialization'; reason='CrySystem/security/bootstrap symbol or callsite context'
        if any(x.lower() in text for x in ['wsarecv','recv','wsaiocontrol','wsaioctl']) or '119fd0' in text:
            cls='ordinary import usage'; reason='concrete edge touches receive import/external symbol but no write-to-IAT installer proven'
        if ('write' in text or 'set' in text or 'store' in text) and any(x.lower() in text for x in ['wsarecv','recv','119fd0']):
            cls='hook installation'; reason='write/store involving receive slot candidate; verify disassembly row details'
        rr=dict(r); rr['classification']=cls; rr['classification_reason']=reason; out.append(rr)
    return out

def read_csv(path):
    if not path.exists(): return []
    with path.open(newline='',encoding='utf-8') as f: return list(csv.DictReader(f))

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    path_rows=[]
    for label,p in [('repo',REPO),('primary_root',DEC),('installed_game',EURO/'game.dll'),('installed_crysystem',EURO/'crysystem.dll'),('requested_mapped',DEC/'game_unpacked_background'/'game_mapped.bin'),('ghidra',GH),('ghidra_project',PROJ)]:
        exists=p.exists(); row={'label':label,'path':str(p),'exists':exists}
        if exists and p.is_file(): row.update({'size':p.stat().st_size,'sha256':sha256(p)})
        path_rows.append(row)
    write_csv(OUT/'verified_paths_hashes.csv',path_rows,['label','path','exists','size','sha256'])
    best,cands=validate_candidates()
    if not best:
        decision={'phase':'pass666_recv_boundary','acceptance':'C','exact_blocker':'No existing mapped Game image candidates found under requested path or prior outbox candidates.','smallest_next_action':'recover mapped game.dll image from prior runtime capture or rerun isolated mapper only'}
        write_json(OUT/'pass666_decision.json',decision); return
    game_path,game_pe,game_sha,winsock=best
    slot_rows=[]
    for i in winsock:
        if i['function'] in TARGET_FUNCS or i['dll'].lower().startswith('ws2_32'):
            slot_rows.append({'mapped_game_path':str(game_path),'mapped_game_sha256':game_sha,**i})
    write_csv(OUT/'game_winsock_iat_slots.csv',slot_rows,['mapped_game_path','mapped_game_sha256','dll','function','ordinal','kind','iat_slot_rva','iat_slot_va'])
    slot_arg=','.join(r['iat_slot_va'] for r in slot_rows)
    gh_results=[]
    gh_results.append(run_ghidra('game.dll','Pass666GameIatXrefs.java',[str(OUT),slot_arg]))
    gh_results.append(run_ghidra_import(EURO/'crysystem.dll','Pass666CrySystemExport.java',[str(OUT)]))
    write_json(OUT/'ghidra_runs.json',gh_results)
    edge_files=[OUT/'game_iat_edges.csv',OUT/'crysystem_edges.csv']
    edges=[]
    for ef in edge_files: edges.extend(read_csv(ef))
    classified=classify_edges(edges)
    write_csv(OUT/'classified_edges.csv',classified,sorted({k for r in classified for k in r.keys()} or {'classification'}))
    has_hook=any(r.get('classification')=='hook installation' for r in classified)
    has_boot=any(r.get('classification')=='security/bootstrap initialization' for r in classified)
    acceptance='A' if has_hook else ('B' if has_boot else 'C')
    blocker=''
    if acceptance=='C':
        blocker='Mapped image parsed, but no Winsock imports were proven from that mapped image; Ghidra project has external/import slot symbols but bounded export did not prove active hook installer or exact CrySystem/AegInitEngine call arguments.'
    decision={'phase':'pass666_recv_boundary','created_at':now(),'acceptance':acceptance,'mapped_game_path':str(game_path),'mapped_game_sha256':game_sha,'mapped_game_is_pe':game_pe.is_pe,'mapped_game_image_base':hx(game_pe.image_base),'mapped_game_size_of_image':hx(game_pe.size_of_image),'winsock_iat_slots':slot_rows,'ghidra_runs':gh_results,'concrete_edge_count':len(classified),'hook_installation_edges':[r for r in classified if r.get('classification')=='hook installation'],'bootstrap_edges':[r for r in classified if r.get('classification')=='security/bootstrap initialization'],'ordinary_import_edges':[r for r in classified if r.get('classification')=='ordinary import usage'],'exact_blocker':blocker,'smallest_next_action':'If C holds, capture/recover missing runtime page/range containing actual IAT slot writes or import-slot xrefs; otherwise validate the proven edge in the next bounded pass.'}
    write_json(OUT/'pass666_decision.json',decision)
    summary=[f"# Pass666 Receive Boundary",f"acceptance={acceptance}",f"mapped_game={game_path}",f"mapped_game_sha256={game_sha}",f"winsock_slots={len(slot_rows)}",f"edges={len(classified)}",f"blocker={blocker}"]
    (OUT/'pass666_summary.md').write_text('\n'.join(summary)+'\n',encoding='utf-8')

if __name__=='__main__': main()

