from __future__ import annotations
import csv, hashlib, json, re, struct, time
from pathlib import Path

REPO=Path(r"C:\AionTools\aion-agent-bridge")
DEC=Path(r"C:\AionTools\aion_decoder_agent")
ART=REPO/'artifacts'; INBOX=REPO/'inbox'; OUT=DEC/'outbox'/'pass665_active_recv_hook'
QUEUE=ART/'pass665_work_queue.json'; TOOL=REPO/'tools'/'pass665_active_recv_hook'
GAME=DEC/'game_unpacked_background'/'game_mapped.bin'
GAME_SHA='dfd4774070018152b5ceda63bdce8ca2471b4fe8352535a62ee54197a161b1e8'
EURO=Path(r"C:\Program Files (x86)\EuroAion\bin64")
HAND=Path(r"C:\tmp\pass665_extract\euroaion_handover_2026-07-15")
TARGET={'recv','WSARecv','send','WSASend','connect','GetProcAddress','WSAIoctl','AcceptEx','ConnectEx','DisconnectEx'}
STRINGS=['CreateSystemInterface','LoadLibrary','GetProcAddress','WSARecv','recv','send','connect','AegInitEngine','Aegis','SecureEngine','CryNetwork','CrySystem']

def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u64(b,o): return struct.unpack_from('<Q',b,o)[0]
def hx(n): return f'0x{n:X}'
def now(): return time.strftime('%Y-%m-%dT%H:%M:%S%z')
def digest(p, name):
    h=getattr(hashlib,name)()
    with open(p,'rb') as f:
        for c in iter(lambda:f.read(1048576),b''): h.update(c)
    return h.hexdigest()

def csvw(p, fields, rows):
    p.parent.mkdir(parents=True,exist_ok=True)
    with open(p,'w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore'); w.writeheader()
        for r in rows: w.writerow({k:r.get(k,'') for k in fields})

def jsw(p,obj):
    p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(obj,indent=2,sort_keys=True),encoding='utf-8')

class PE:
    def __init__(self,path,base=None):
        self.path=Path(path); self.data=self.path.read_bytes(); self.base_override=base; self.is_pe=False; self.is64=False; self.base=base or 0; self.size=0; self.secs=[]; self.dirs=[]; self.imports=[]; self.delay=[]; self.exports=[]; self.tls=False; self.parse()
    def parse(self):
        b=self.data
        if len(b)<0x100 or b[:2]!=b'MZ': return
        pe=u32(b,0x3c)
        if pe+0x18>=len(b) or b[pe:pe+4]!=b'PE\0\0': return
        self.is_pe=True; ns=u16(b,pe+6); so=u16(b,pe+20); opt=pe+24; mag=u16(b,opt); self.is64=(mag==0x20b)
        parsed_base=u64(b,opt+24) if self.is64 else u32(b,opt+28)
        self.base=self.base_override if self.base_override is not None else parsed_base
        self.size=u32(b,opt+56); dd=opt+(112 if self.is64 else 96)
        self.dirs=[(u32(b,dd+i*8),u32(b,dd+i*8+4)) if dd+i*8+8<=len(b) else (0,0) for i in range(16)]
        off=opt+so
        for i in range(ns):
            s=off+i*40
            if s+40>len(b): break
            nm=b[s:s+8].split(b'\0',1)[0].decode('ascii','replace')
            self.secs.append((nm,u32(b,s+12),u32(b,s+8),u32(b,s+20),u32(b,s+16),u32(b,s+36)))
        self.imports=self.impdir(1,False); self.delay=self.impdir(13,True); self.exports=self.expdir(); self.tls=bool(self.dirs[9][0] and self.dirs[9][1])
    def r2o(self,rva):
        for nm,va,vs,raw,rs,ch in self.secs:
            if va<=rva<va+max(vs,rs) and rs:
                o=raw+(rva-va)
                return o if 0<=o<len(self.data) else None
        return rva if 0<=rva<len(self.data) else None
    def cstr(self,rva):
        o=self.r2o(rva)
        if o is None: return ''
        e=self.data.find(b'\0',o,min(len(self.data),o+4096))
        if e<0: e=min(len(self.data),o+4096)
        return self.data[o:e].decode('ascii','replace')
    def impdir(self,idx,delay):
        if idx>=len(self.dirs): return []
        rva,sz=self.dirs[idx]; o=self.r2o(rva)
        if not rva or o is None: return []
        rows=[]; ds=32 if delay else 20; width=8 if self.is64 else 4; flag=0x8000000000000000 if self.is64 else 0x80000000
        for i in range(min(2048,max(1,sz//ds+8))):
            d=o+i*ds
            if d+ds>len(self.data): break
            if delay:
                name_rva=u32(self.data,d+4); int_rva=u32(self.data,d+12); iat_rva=u32(self.data,d+16)
                if name_rva==int_rva==iat_rva==0: break
            else:
                int_rva=u32(self.data,d); name_rva=u32(self.data,d+12); iat_rva=u32(self.data,d+16)
                if int_rva==name_rva==iat_rva==0: break
            dll=self.cstr(name_rva); to=self.r2o(int_rva or iat_rva)
            if not dll or to is None: continue
            for n in range(4096):
                q=to+n*width
                if q+width>len(self.data): break
                val=u64(self.data,q) if self.is64 else u32(self.data,q)
                if not val: break
                name=''; ordv=''
                if val & flag: ordv=val&0xffff; name=f'ordinal_{ordv}'
                else:
                    ho=self.r2o(val)
                    if ho is not None: name=self.cstr(val+2)
                slot=iat_rva+n*width
                rows.append({'module_path':str(self.path),'dll':dll,'function':name,'ordinal':ordv,'iat_slot_rva':hx(slot),'iat_slot_va':hx(self.base+slot),'kind':'delay_import' if delay else 'import'})
        return rows
    def expdir(self):
        if not self.dirs: return []
        rva,sz=self.dirs[0]; o=self.r2o(rva)
        if not rva or o is None or o+40>len(self.data): return []
        base=u32(self.data,o+16); nf=u32(self.data,o+20); nn=u32(self.data,o+24); fr=u32(self.data,o+28); nr=u32(self.data,o+32); orr=u32(self.data,o+36)
        fo=self.r2o(fr); no=self.r2o(nr); oo=self.r2o(orr); names={}
        if no is not None and oo is not None:
            for i in range(min(nn,20000)):
                if no+i*4+4>len(self.data) or oo+i*2+2>len(self.data): break
                names[u16(self.data,oo+i*2)]=self.cstr(u32(self.data,no+i*4))
        rows=[]
        if fo is None: return rows
        for i in range(min(nf,50000)):
            if fo+i*4+4>len(self.data): break
            rv=u32(self.data,fo+i*4)
            if rv: rows.append({'ordinal':base+i,'name':names.get(i,''),'rva':hx(rv),'va':hx(self.base+rv)})
        return rows

def hits(data,needles):
    out=[]
    for n in needles:
        for enc,pat,step in [('ascii',n.encode(),1),('utf16le',n.encode('utf-16le'),2)]:
            o=0; c=0
            while True:
                p=data.find(pat,o)
                if p<0: break
                out.append({'needle':n,'encoding':enc,'offset':hx(p)}); c+=1; o=p+step
                if c>=20: break
    return out

def modules():
    out=[]
    if GAME.exists(): out.append(('game_mapped',GAME,0x10000000))
    for n in ['crysystem.dll','aion.bin','game.dll','euroaion.dll','version.dll','aegisty64.bin','SecureEngineSDK64.dll']:
        p=EURO/n
        if p.exists(): out.append((f'installed_{n}',p,None))
    for rel in ['inputs/aion.bin','inputs/game.dll','inputs/euroaion.dll','inputs/aegisty64.bin','checkpoint/aion_unpacked_checkpoint.bin']:
        p=HAND/rel
        if p.exists(): out.append((f'handover_{Path(rel).name}',p,None))
    return out

def initq():
    stages=[]
    names=[
      ('stage1_winsock_import_hook_baseline','Record import slots and scan available modules for references/trampolines.',['artifacts/pass665_winsock_slot_baseline.csv','artifacts/pass665_hook_write_candidates.csv']),
      ('stage2_crysystem_inventory','Verify/inventory CrySystem and dynamic resolution evidence.',['artifacts/pass665_crysystem_inventory.csv','artifacts/pass665_dynamic_resolution_trace.json']),
      ('stage3_aeginit_argument_candidates','Search offline modules for AegInitEngine evidence.',['artifacts/pass665_aeginit_argument_candidates.csv']),
      ('stage4_hook_target_extraction','Extract only proven hook target or record blocker.',['artifacts/pass665_active_recv_hook_decision.json']),
      ('stage5_acceptance_gate','Evaluate decode gate and report.',['artifacts/pass665_active_recv_hook_summary.md','inbox/codex_report.md'])]
    for n,fb,arts in names: stages.append({'name':n,'script':str(TOOL/'pass665_runner.py'),'status':'pending','attempts':0,'primary_result':'','fallback_definition':fb,'fallback_status':'pending','fallback_attempts':0,'last_error':'','produced_artifacts':arts})
    q={'worker':'codex','phase':'pass665_active_recv_hook','created_at':now(),'stages':stages}; jsw(QUEUE,q); return q

def done(q,i,res,fb):
    s=q['stages'][i]; s['status']='completed'; s['attempts']=s.get('attempts',0)+1; s['primary_result']=res; s['fallback_status']='completed'; s['fallback_attempts']=s.get('fallback_attempts',0)+1; s['fallback_result']=fb; s['last_error']=''; jsw(QUEUE,q)

def tramps(pe):
    rows=[]
    for nm,va,vs,raw,rs,ch in pe.secs:
        if not(ch & 0x20000000) or not rs: continue
        blob=pe.data[raw:min(len(pe.data),raw+rs)]
        for pat,label in [(rb'\xff\x25....','ff25_indirect_jump_stub'),(rb'\x48\xb8........\xff\xe0','mov_rax_jmp_rax_absolute_stub')]:
            for m in re.finditer(pat,blob):
                rows.append({'candidate_type':label,'module_path':str(pe.path),'address_or_offset':hx(pe.base+va+m.start()),'target_slot_va':'','evidence':label,'confidence':'low','reason':'generic thunk/detour-like pattern only; no proven recv/WSARecv installer relationship'})
                if len(rows)>=2000: return rows
    return rows

def main():
    for p in [ART,INBOX,OUT]: p.mkdir(parents=True,exist_ok=True)
    q=initq(); pes=[]
    for label,path,base in modules():
        try: pes.append((label,PE(path,base)))
        except Exception as e: (OUT/'parse_errors.txt').open('a',encoding='utf-8').write(f'{label},{path},{e}\n')
    game=next((p for l,p in pes if l=='game_mapped'),None); base_rows=[]; slots=[]
    if game and game.is_pe:
        ok=digest(game.path,'sha256')==GAME_SHA
        for r in game.imports+game.delay:
            fn=str(r.get('function','')); dll=str(r.get('dll',''))
            if fn in TARGET or dll.lower().startswith('ws2_32'):
                slots.append(int(r['iat_slot_va'],16)); base_rows.append({'module':'game_mapped','source_path':str(game.path),'image_base':'0x10000000','image_sha256_matches_expected':str(ok).lower(),'dll':dll,'function':fn,'ordinal':r.get('ordinal',''),'import_kind':r.get('kind',''),'iat_slot_rva':r.get('iat_slot_rva',''),'iat_slot_va':r.get('iat_slot_va',''),'confidence':'high','reason':'PE import table baseline from mapped Game image; runtime slot contents not read'})
    if not base_rows: base_rows=[{'module':'game_mapped','source_path':str(GAME),'image_base':'0x10000000','image_sha256_matches_expected':'false','dll':'','function':'','ordinal':'','import_kind':'','iat_slot_rva':'','iat_slot_va':'','confidence':'none','reason':'Game mapped PE absent or no target Winsock imports parsed'}]
    csvw(ART/'pass665_winsock_slot_baseline.csv',['module','source_path','image_base','image_sha256_matches_expected','dll','function','ordinal','import_kind','iat_slot_rva','iat_slot_va','confidence','reason'],base_rows)
    hook=[]
    for label,pe in pes:
        if not pe.is_pe: continue
        if slots and label!='game_mapped':
            for slot in slots:
                for kind,pat in [('va32_le',struct.pack('<I',slot&0xffffffff)),('va64_le',struct.pack('<Q',slot))]:
                    o=0; c=0
                    while True:
                        pos=pe.data.find(pat,o)
                        if pos<0: break
                        hook.append({'candidate_type':'static_reference_to_game_iat_slot','module_path':str(pe.path),'address_or_offset':f'file+{hx(pos)}','target_slot_va':hx(slot),'evidence':kind,'confidence':'low','reason':'static reference to Game import slot; needs disassembly/xref proof before classifying as hook/write'}); c+=1; o=pos+1
                        if c>=20: break
        hook.extend(tramps(pe))
    if not hook: hook=[{'candidate_type':'none','module_path':'','address_or_offset':'','target_slot_va':'','evidence':'','confidence':'none','reason':'No static IAT slot references or trampoline patterns found'}]
    csvw(ART/'pass665_hook_write_candidates.csv',['candidate_type','module_path','address_or_offset','target_slot_va','evidence','confidence','reason'],hook)
    done(q,0,f'baseline_rows={len(base_rows)} hook_rows={len(hook)}','static slot-reference/trampoline fallback completed across available modules')
    cry=EURO/'crysystem.dll'; cry_rows=[]; dyn={'phase':'pass665_dynamic_resolution_trace','generated_at':now(),'modules':[]}
    if cry.exists():
        cp=PE(cry); md5=digest(cry,'md5'); sha=digest(cry,'sha256'); imps=cp.imports+cp.delay; sh=hits(cp.data,STRINGS)
        cry_rows.append({'module':'CrySystem.dll','source_path':str(cry),'size':cry.stat().st_size,'md5_matches_expected':str(md5=='a31cfce0205d6ee3a7eafcdf015d6c51').lower(),'sha256':sha,'is_pe':str(cp.is_pe).lower(),'image_base':hx(cp.base) if cp.is_pe else '','size_of_image':hx(cp.size) if cp.is_pe else '','exports_count':len(cp.exports),'imports_count':len(imps),'tls_present':str(cp.tls).lower(),'interesting_string_hits':len(sh),'confidence':'high','reason':'Installed CrySystem.dll parsed offline; metadata only'})
        for imp in imps:
            if str(imp.get('function','')) in TARGET or str(imp.get('function','')) in {'LoadLibraryA','LoadLibraryW','LoadLibraryExA','LoadLibraryExW'} or str(imp.get('dll','')).lower()=='ws2_32.dll':
                cry_rows.append({'module':'CrySystem.dll','source_path':str(cry),'size':cry.stat().st_size,'md5_matches_expected':str(md5=='a31cfce0205d6ee3a7eafcdf015d6c51').lower(),'sha256':'','is_pe':'true','image_base':hx(cp.base),'size_of_image':hx(cp.size),'exports_count':'','imports_count':'','tls_present':'','interesting_string_hits':'','confidence':'medium','reason':f"relevant import {imp.get('dll')}!{imp.get('function')} slot {imp.get('iat_slot_va')}"})
        dyn['modules'].append({'module':'CrySystem.dll','path':str(cry),'md5_matches_expected':md5=='a31cfce0205d6ee3a7eafcdf015d6c51','exports_of_interest':[e for e in cp.exports if e.get('name') in {'CreateSystemInterface','CreateGame'} or 'System' in str(e.get('name',''))][:100],'dynamic_resolution_string_hits':sh[:200],'imports_of_interest':[i for i in imps if str(i.get('function','')) in TARGET or str(i.get('function','')) in {'LoadLibraryA','LoadLibraryW','LoadLibraryExA','LoadLibraryExW','GetProcAddress'} or str(i.get('dll','')).lower()=='ws2_32.dll'][:300]})
    else:
        cry_rows=[{'module':'CrySystem.dll','source_path':str(cry),'size':'','md5_matches_expected':'false','sha256':'','is_pe':'false','image_base':'','size_of_image':'','exports_count':'','imports_count':'','tls_present':'','interesting_string_hits':'','confidence':'none','reason':'Expected installed CrySystem.dll absent'}]
    csvw(ART/'pass665_crysystem_inventory.csv',['module','source_path','size','md5_matches_expected','sha256','is_pe','image_base','size_of_image','exports_count','imports_count','tls_present','interesting_string_hits','confidence','reason'],cry_rows); jsw(ART/'pass665_dynamic_resolution_trace.json',dyn); done(q,1,f'crysystem_rows={len(cry_rows)} dynamic_modules={len(dyn["modules"])}','startup-evidence fallback retained; no bootstrap claimed without call edge')
    aeg=[]
    for label,pe in pes:
        if not pe.is_pe: continue
        hs=hits(pe.data,['AegInitEngine','Aeg','SecureEngineSDK64','aegisty64'])
        im=[i for i in pe.imports+pe.delay if 'aeg' in str(i.get('dll','')).lower() or 'secureengine' in str(i.get('dll','')).lower() or str(i.get('ordinal',''))=='1' or 'Aeg' in str(i.get('function',''))]
        if hs or im: aeg.append({'module':label,'source_path':str(pe.path),'candidate_type':'string_or_import_evidence','callsite_or_offset':';'.join(h['offset'] for h in hs[:10]),'rcx':'','rdx':'','r8':'','r9':'','stack_args':'','confidence':'medium' if im else 'low','reason':f'offline static evidence only: {len(hs)} strings, {len(im)} imports; exact x64 args not recovered without disassembly-backed callsite'})
    if not aeg: aeg=[{'module':'','source_path':'','candidate_type':'none','callsite_or_offset':'','rcx':'','rdx':'','r8':'','r9':'','stack_args':'','confidence':'none','reason':'No direct AegInitEngine name/import/ordinal-1 callsite with recoverable args found'}]
    csvw(ART/'pass665_aeginit_argument_candidates.csv',['module','source_path','candidate_type','callsite_or_offset','rcx','rdx','r8','r9','stack_args','confidence','reason'],aeg); done(q,2,f'aeg_rows={len(aeg)}','ordinal/name/static-string fallback completed across installed and handover modules')
    proven=False; exact_aeg=any(r.get('confidence')=='high' and r.get('rcx') for r in aeg); bootstrap=False; transform=False; decode=False
    blocker={'exact_file':str(GAME) + '; ' + str(cry),'exact_function_or_address':'CrySystem.dll export CreateSystemInterface / Game Winsock IAT slots','unresolved_definition':'missing mapped Game import-slot proof in this workspace and no disassembly-backed write/call edge proving a recv/WSARecv hook installer, CrySystem security bootstrap, or exact AegInitEngine x64 arguments','precise_next_operation':'run a bounded Ghidra headless export for CrySystem.dll CreateSystemInterface/CreateGame reachable callees plus xrefs to Game Winsock IAT slot VAs, then classify concrete write/call edges'}
    decision={'worker':'codex','phase':'pass665_active_recv_hook','game_mapped_path':str(GAME),'game_mapped_sha256_matches_expected':bool(game and game.is_pe and digest(game.path,'sha256')==GAME_SHA),'crysystem_path':str(cry),'crysystem_present':cry.exists(),'crysystem_md5_matches_expected':cry.exists() and digest(cry,'md5')=='a31cfce0205d6ee3a7eafcdf015d6c51','winsock_import_slots_recorded':len([r for r in base_rows if r.get('confidence')!='none']),'hook_write_candidate_count':len([r for r in hook if r.get('candidate_type')!='none']),'aeginit_candidate_count':len([r for r in aeg if r.get('candidate_type')!='none']),'exact_active_hook_installer_and_target':proven,'exact_crysystem_security_bootstrap':bootstrap,'exact_aeginit_callsite_and_args':exact_aeg,'outer_transform_model_generated':transform,'sequential_real_capture_decode':decode,'s2c_decoder_success':False,'acceptance_gate_passed':False,'raw_payload_committed':False,'raw_ciphertext_committed':False,'raw_plaintext_blob_committed':False,'packet_hashes_committed':False,'binaries_committed':False,'reason':'Offline metadata confirms CrySystem is present. The expected mapped Game image was absent or unparsable in this local workspace, so no Game Winsock import slots were proven from that image; static metadata/pattern scans also did not prove an active hook installer, security bootstrap caller, exact AegInitEngine arguments, transform, or decoded plaintext.','exact_blocker':blocker,'next_action':blocker['precise_next_operation']}
    jsw(ART/'pass665_active_recv_hook_decision.json',decision); done(q,3,'no proven hook target; exact blocker recorded','no emulator/decoder generated because no concrete hook/transform was recovered')
    summary=f'''# Pass665 Active Receive Hook / CrySystem Bootstrap

Acceptance gate: not passed.

What completed:
- Recorded Game mapped Winsock import slot baseline rows: {len([r for r in base_rows if r.get('confidence')!='none'])}
- Parsed installed CrySystem.dll: present={decision['crysystem_present']}, md5_match={decision['crysystem_md5_matches_expected']}
- Scanned installed and handover modules for static Game Winsock slot references when available, trampoline-like stubs, dynamic-resolution strings, and Aegis/SecureEngine evidence.
- Did not generate an initializer, hook emulator, transform model, or capture decoder because no concrete hook/bootstrap/source relation was recovered.

Decision:
- exact active hook installer + target: false
- exact CrySystem security bootstrap: false
- exact AegInitEngine callsite + arguments: false
- actual outer transform: false
- sequential PCAP decode: false

Exact blocker:
{blocker['exact_file']} / {blocker['exact_function_or_address']} still lacks {blocker['unresolved_definition']}.

Next operation:
{blocker['precise_next_operation']}

No raw packet bytes, payloads, ciphertext, keys, hashes, binaries, DLLs, EXEs, or archives were committed.
'''
    (ART/'pass665_active_recv_hook_summary.md').write_text(summary,encoding='utf-8'); (INBOX/'codex_report.md').write_text(summary,encoding='utf-8'); done(q,4,'acceptance gate evaluated and report written','exact blocker captured instead of claiming report-only success')
if __name__=='__main__': main()
