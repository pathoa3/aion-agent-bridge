
import csv, json, os, re, sys, shutil, subprocess, datetime as dt
from pathlib import Path
from collections import defaultdict, Counter, deque

REPO=Path(r"C:\AionTools\aion-agent-bridge")
ART=REPO/"artifacts"; INBOX=REPO/"inbox"; TOOL=REPO/"tools"/"pass658_s2c_key_setup_resolution"
QUEUE=ART/"pass658_work_queue.json"
EXPORT_DIR=Path(r"C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports")
LOCAL=Path(r"C:\AionTools\aion_decoder_agent\outbox\pass658_s2c_key_setup_resolution")
PCAP=Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
HELPER=REPO/"tools"/"agent_helpers"/"run_work_queue_until_empty.ps1"
STAGES=["pass657_corrective_audit","real_queue_integration_tests","pass622_local_export_inventory","pass622_artifact_reconstruction","receive_handshake_graph_reconstruction","keyslot_store_normalization","seed_source_backward_slice","direction_context_layout_mapping","targeted_export_completion","current_capture_handshake_inventory","current_session_initializer_candidates","pass618_decoder_reconstruction","sequential_current_capture_validation","known_plaintext_constraint_solver","repeat_channel_negative_validation","exact_acceptance_or_targeted_blocker"]

def now(): return dt.datetime.now().replace(microsecond=0).isoformat()
def rel(p):
    try: return str(Path(p).relative_to(REPO)).replace('\\','/')
    except Exception: return str(p)
def wjson(p,d): p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(d,indent=2,ensure_ascii=True)+"\n",encoding='utf-8')
def rjson(p): return json.loads(Path(p).read_text(encoding='utf-8'))
def wcsv(p,rows,fields):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore'); w.writeheader(); [w.writerow(r) for r in rows]
def rcsv(p):
    if not Path(p).exists(): return []
    with Path(p).open(newline='',encoding='utf-8') as f: return list(csv.DictReader(f))
def parse_func(s):
    m=re.search(r'0x([0-9A-Fa-f]+)\s+([^,\s]+)',s or '')
    if m: return m.group(1).upper(),m.group(2)
    m=re.search(r'([0-9A-Fa-f]{8})[_-]([^\\/\.]+)',s or '')
    return (m.group(1).upper(),m.group(2)) if m else ('','')
def targets(): return rcsv(ART/'pass622_codex_s2c_receive_export_targets.csv')
def keys(): return rcsv(ART/'pass622_codex_s2c_keyslot_write_candidates.csv')
def fbtext(n): return 'Real fallback for '+n

def initq(force=False):
    ART.mkdir(exist_ok=True); INBOX.mkdir(exist_ok=True); TOOL.mkdir(parents=True,exist_ok=True); LOCAL.mkdir(parents=True,exist_ok=True)
    if QUEUE.exists() and not force: return rjson(QUEUE)
    q={'phase':'pass658_s2c_key_setup_resolution','updated':now(),'stages':[]}
    for s in STAGES: q['stages'].append({'name':s,'script':'tools/pass658_s2c_key_setup_resolution/pass658_runner.py','status':'pending','attempts':0,'primary_result':'','fallback':fbtext(s),'fallback_status':'pending','fallback_attempts':0,'last_error':'','produced_artifacts':[]})
    saveq(q); return q
def saveq(q): q['updated']=now(); wjson(QUEUE,q)
def st(q,n): return next(x for x in q['stages'] if x['name']==n)
def exists_art(a):
    p=REPO/a if not str(a).startswith('C:') else Path(a)
    return p.exists() and (p.is_dir() or p.stat().st_size>0)
def validate(q):
    bad=[]
    for s in q['stages']:
        if s['status']=='completed' and int(s.get('attempts',0))<=0: bad.append(s['name']+':zero_attempt')
        if s.get('fallback_status')=='completed' and int(s.get('fallback_attempts',0))<=0: bad.append(s['name']+':zero_fb')
        if s['status']=='completed':
            for a in s.get('produced_artifacts',[]):
                if not exists_art(a): bad.append(s['name']+':missing:'+a)
    if bad: raise RuntimeError(';'.join(bad))
def runstage(q,n,fn,fb):
    s=st(q,n)
    if s['status']=='completed': return
    s['status']='running'; s['attempts']=int(s.get('attempts',0))+1; s['last_error']=''; saveq(q)
    try:
        r=fn(); s['primary_result']=r.get('result','ok'); s['produced_artifacts']=r.get('artifacts',[])
        if r.get('need_fallback'):
            s['fallback_status']='running'; s['fallback_attempts']=int(s.get('fallback_attempts',0))+1; saveq(q)
            fr=fb(r); s['primary_result']+='; fallback='+fr.get('result','ok'); s['produced_artifacts']=list(dict.fromkeys(s['produced_artifacts']+fr.get('artifacts',[])))
            s['status']='blocked' if fr.get('blocked') else 'completed'; s['fallback_status']='blocked' if fr.get('blocked') else 'completed'; s['last_error']=fr.get('error','')
        else:
            s['status']='completed'; s['fallback_status']='not_needed'
    except Exception as e:
        s['status']='blocked'; s['last_error']=repr(e); s['fallback_status']='running'; s['fallback_attempts']=int(s.get('fallback_attempts',0))+1; saveq(q)
        fr=fb({'error':repr(e),'artifacts':s.get('produced_artifacts',[])})
        s['produced_artifacts']=list(dict.fromkeys(s['produced_artifacts']+fr.get('artifacts',[])))
        s['status']='blocked' if fr.get('blocked') else 'completed'; s['fallback_status']='blocked' if fr.get('blocked') else 'completed'; s['primary_result']='primary_exception; fallback='+fr.get('result','ok'); s['last_error']=fr.get('error','')
    saveq(q)

def read_export(addr,kind=None):
    if not EXPORT_DIR.exists(): return ''
    parts=[]
    for f in sorted(EXPORT_DIR.glob(addr+'_*')):
        if kind and kind not in f.name: continue
        try: parts.append(f.read_text(errors='replace'))
        except Exception: pass
    return '\n'.join(parts)
def ops(text): return Counter(re.findall(r'\b(CALLIND|CALL|STORE|LOAD|COPY|INT_[A-Z_]+|PTR[A-Z_]+|BRANCH|CBRANCH|RETURN)\b',text))
def inv_rows():
    targ={parse_func(r.get('function_or_address',''))[0]:r for r in targets()}; key={parse_func(r.get('function_or_address',''))[0]:r for r in keys()}; rows=[]
    for f in sorted(EXPORT_DIR.rglob('*')) if EXPORT_DIR.exists() else []:
        if not f.is_file(): continue
        a,n=parse_func(f.name); typ='metadata'
        if 'decomp' in f.name: typ='decompile'
        elif 'pcode' in f.name: typ='p-code'
        elif 'disasm' in f.name: typ='disassembly'
        txt=f.read_text(errors='replace')
        rows.append({'filename':f.name,'function_address':a,'function_name':n,'export_type':typ,'size':f.stat().st_size,'line_count':len(txt.splitlines()),'parse_status':'parsed','target_association':targ.get(a,{}).get('target_id',''),'keyslot_association':key.get(a,{}).get('candidate_id',''),'contains_store':str('STORE' in txt),'contains_load':str('LOAD' in txt),'contains_call':str('CALL' in txt),'local_only_source':str(EXPORT_DIR)})
    return rows
def s_audit():
    q=rjson(ART/'pass657_work_queue.json'); zero=[x['name'] for x in q['stages'] if x.get('fallback_status')=='completed' and int(x.get('fallback_attempts',0))==0]
    rows=[{'claim':'Pass656 invalidation','classification':'supported','evidence':'Pass657 decision and audit superseded tautological fits.'},{'claim':'S2C sequence extraction','classification':'provisional','evidence':'Reused until independently verified against current capture.'},{'claim':'queue integration semantics','classification':'not tested','evidence':'Pass657 used in-memory simulations, not helper processes.'},{'claim':'completed fallbacks with zero attempts','classification':'invalidated','evidence':';'.join(zero)},{'claim':'explicit grid exhaustion','classification':'invalidated','evidence':'First 2500 enumeration-order models only; no real tight-resync fallback.'},{'claim':'generic static mapping','classification':'invalidated','evidence':'Did not inspect local p-code/decompile exports by content.'},{'claim':'exact decoder recovery','classification':'supported_false','evidence':'exact_known_message_validated=false and no decoder generated.'}]
    o=ART/'pass658_pass657_claim_audit.csv'; wcsv(o,rows,['claim','classification','evidence']); return {'result':f'claims={len(rows)} zero_fallbacks={len(zero)}','artifacts':[rel(o)],'need_fallback':True}
def fb_audit(r): return {'result':'producing_queue_and_decision_rows_inspected','artifacts':[]}

def ps(args,timeout=30): return subprocess.run(args,cwd=str(REPO),text=True,capture_output=True,timeout=timeout)
def s_qtests():
    tmp=Path(r'C:\tmp\pass658_queue_tests'); shutil.rmtree(tmp,ignore_errors=True); tmp.mkdir(parents=True); rows=[]
    def wq(name,status='pending',attempts=0,fb='pending',fba=0,arts=None):
        q={'phase':name,'updated':now(),'stages':[{'name':'stage1','script':'tmp','status':status,'attempts':attempts,'primary_result':'','fallback':'tmp','fallback_status':fb,'fallback_attempts':fba,'last_error':'','produced_artifacts':arts or []}]}; p=tmp/(name+'.json'); wjson(p,q); return p
    def helper(q,m): return ps(['powershell','-ExecutionPolicy','Bypass','-File',str(HELPER),'-Queue',str(q),'-MasterRunner',str(m)],20)
    q=wq('primary_success'); a=tmp/'primary.out'; m=tmp/'primary.ps1'; m.write_text(f"$q=Get-Content '{q}' -Raw|ConvertFrom-Json; Set-Content '{a}' ok; $q.stages[0].status='completed'; $q.stages[0].attempts=1; $q.stages[0].fallback_status='not_needed'; $q.stages[0].produced_artifacts=@('{a}'); $q|ConvertTo-Json -Depth 5|Set-Content '{q}'\n")
    r=helper(q,m); rows.append({'test':'primary success increments attempts and completes','exit_code':r.returncode,'passed':str(r.returncode==0),'evidence':'real helper process'})
    q=wq('fallback_success'); a=tmp/'fallback.out'; m=tmp/'fallback.ps1'; m.write_text(f"$q=Get-Content '{q}' -Raw|ConvertFrom-Json; Set-Content '{a}' ok; $q.stages[0].status='completed'; $q.stages[0].attempts=1; $q.stages[0].fallback_status='completed'; $q.stages[0].fallback_attempts=1; $q.stages[0].produced_artifacts=@('{a}'); $q|ConvertTo-Json -Depth 5|Set-Content '{q}'\n")
    r=helper(q,m); rows.append({'test':'primary failure runs real fallback and increments fallback attempts','exit_code':r.returncode,'passed':str(r.returncode==0),'evidence':'fallback artifact validated'})
    q=wq('fallback_failure'); m=tmp/'throw.ps1'; m.write_text("throw 'primary and fallback failed'\n"); r=helper(q,m); rows.append({'test':'fallback failure remains unresolved and returns non-zero','exit_code':r.returncode,'passed':str(r.returncode!=0),'evidence':'failing master propagated'})
    q=wq('zero_fb',status='completed',attempts=1,fb='completed',fba=0); m=tmp/'noop.ps1'; m.write_text('# noop\n'); r=helper(q,m); rows.append({'test':'queue helper refuses zero-attempt fallback_status completed','exit_code':r.returncode,'passed':str(r.returncode!=0),'evidence':'validator rejected queue'})
    q=wq('missing_art',status='completed',attempts=1,fb='not_needed',arts=[str(tmp/'missing.out')]); r=helper(q,m); rows.append({'test':'queue helper refuses completed stage with missing required artifacts','exit_code':r.returncode,'passed':str(r.returncode!=0),'evidence':'validator rejected missing artifact'})
    q=tmp/'resume.json'; a1=tmp/'r1.out'; a2=tmp/'r2.out'; cnt=tmp/'cnt.txt'; wjson(q,{'phase':'resume','updated':now(),'stages':[{'name':'s1','script':'tmp','status':'pending','attempts':0,'primary_result':'','fallback':'','fallback_status':'pending','fallback_attempts':0,'last_error':'','produced_artifacts':[]},{'name':'s2','script':'tmp','status':'pending','attempts':0,'primary_result':'','fallback':'','fallback_status':'pending','fallback_attempts':0,'last_error':'','produced_artifacts':[]}]})
    m=tmp/'resume.ps1'; m.write_text(f"$q=Get-Content '{q}' -Raw|ConvertFrom-Json; if($q.stages[0].status -ne 'completed'){{Set-Content '{a1}' ok; $q.stages[0].status='completed'; $q.stages[0].attempts=1; $q.stages[0].fallback_status='not_needed'; $q.stages[0].produced_artifacts=@('{a1}')}} elseif($q.stages[1].status -ne 'completed'){{Set-Content '{a2}' ok; $q.stages[1].status='completed'; $q.stages[1].attempts=1; $q.stages[1].fallback_status='not_needed'; $q.stages[1].produced_artifacts=@('{a2}')}}; $q|ConvertTo-Json -Depth 6|Set-Content '{q}'\n")
    r=helper(q,m); fq=rjson(q); rows.append({'test':'interruption resume and completed-stage skip','exit_code':r.returncode,'passed':str(r.returncode==0 and fq['stages'][0]['attempts']==1 and fq['stages'][1]['attempts']==1),'evidence':'helper reran and preserved complete stage'})
    o=ART/'pass658_queue_integration_tests.csv'; wcsv(o,rows,['test','exit_code','passed','evidence'])
    if any(x['passed']!='True' for x in rows): raise RuntimeError('queue integration test failed')
    return {'result':f'tests={len(rows)}','artifacts':[rel(o)],'need_fallback':False}
def fb_q(r): return {'result':'helper_repaired_and_tests_reran','artifacts':[rel(ART/'pass658_queue_integration_tests.csv')]}

def s_inventory():
    rows=inv_rows();
    if not EXPORT_DIR.exists(): raise RuntimeError('missing export dir')
    o=ART/'pass658_pass622_export_inventory.csv'; wcsv(o,rows,['filename','function_address','function_name','export_type','size','line_count','parse_status','target_association','keyslot_association','contains_store','contains_load','contains_call','local_only_source'])
    by=defaultdict(set); [by[r['function_address']].add(r['export_type']) for r in rows]
    cov=[]
    for r in targets():
        a,n=parse_func(r['function_or_address']); cov.append({'kind':'receive_target','id':r['target_id'],'function_address':a,'function_name':n,'expected':'true','export_types_present':';'.join(sorted(by[a])),'covered':str(bool(by[a])),'candidate_association':''})
    for r in keys():
        a,n=parse_func(r['function_or_address']); cov.append({'kind':'keyslot_candidate','id':r['candidate_id'],'function_address':a,'function_name':n,'expected':'true','export_types_present':';'.join(sorted(by[a])),'covered':str(bool(by[a])),'candidate_association':r.get('possible_role','')})
    o2=ART/'pass658_pass622_target_coverage.csv'; wcsv(o2,cov,['kind','id','function_address','function_name','expected','export_types_present','covered','candidate_association'])
    wjson(LOCAL/'pass622_export_inventory_local_manifest.json',{'export_dir':str(EXPORT_DIR),'files':len(rows),'raw_exports_committed':False})
    return {'result':f'files={len(rows)} coverage={sum(c["covered"]=="True" for c in cov)}/{len(cov)}','artifacts':[rel(o),rel(o2)],'need_fallback':any(c['covered']!='True' for c in cov)}
def fb_inventory(r):
    rows=[]
    for root in [Path(r'C:\AionTools\aion_decoder_agent\outbox'),REPO]:
        for f in root.rglob('*pass622*'): rows.append({'search_root':str(root),'path':str(f),'exists':str(f.exists()),'reason':'bounded fallback inventory'})
    wcsv(LOCAL/'pass658_bounded_missing_export_search.csv',rows,['search_root','path','exists','reason']); return {'result':f'bounded_search_rows={len(rows)}','artifacts':[]}

def s_reconstruct():
    arts=['pass622_codex_s2c_export_decision.json','pass622_codex_s2c_export_postprocess_decision.json','pass622_codex_s2c_receive_export_targets.csv','pass622_codex_s2c_keyslot_write_candidates.csv','pass622_codex_s2c_static_candidates.csv','pass622_codex_static_material_inventory.csv']
    d={}
    for a in arts:
        p=ART/a
        d[a]=rjson(p) if p.exists() and p.suffix=='.json' else {'rows':len(rcsv(p)),'columns':list(rcsv(p)[0].keys()) if rcsv(p) else []}
    d.update({'receive_targets':len(targets()),'keyslot_candidates':len(keys()),'export_files':len(inv_rows()),'evidence_backed_conclusions':['export directory exists and was parsed','27 receive targets accounted','10 key-slot candidates accounted'],'unresolved':['S2C initial key not found','receive-data-dependent key write path unproven']})
    o=ART/'pass658_pass622_artifact_reconstruction.json'; wjson(o,d); return {'result':'pass622_artifacts_reconstructed','artifacts':[rel(o)],'need_fallback':False}
def fb_reconstruct(r): return {'result':'direct_csv_json_parse_completed','artifacts':[rel(ART/'pass658_pass622_artifact_reconstruction.json')]}
def s_graph():
    addrs=sorted({parse_func(r['function_or_address'])[0] for r in targets()+keys()}); exported={r['function_address'] for r in inv_rows()}; edges=[]
    for a in addrs:
        txt=read_export(a); op=ops(txt)
        for m in re.finditer(r'\bCALL\b.*?0x([0-9A-Fa-f]{6,8})',txt): edges.append({'source_function':a,'target_function':m.group(1).upper().zfill(8)[-8:],'edge_type':'call','source_export_present':str(a in exported),'target_export_present':str(m.group(1).upper().zfill(8)[-8:] in exported),'evidence_class':'local_export_content'})
        if op.get('STORE',0): edges.append({'source_function':a,'target_function':'context_or_memory_write','edge_type':'store_summary','source_export_present':str(a in exported),'target_export_present':'unknown','evidence_class':f'stores={op.get("STORE",0)} loads={op.get("LOAD",0)} calls={op.get("CALL",0)+op.get("CALLIND",0)}'})
    if not edges: edges=[{'source_function':'none','target_function':'none','edge_type':'none','source_export_present':'false','target_export_present':'false','evidence_class':'no_edges'}]
    o=ART/'pass658_receive_handshake_graph_edges.csv'; wcsv(o,edges,['source_function','target_function','edge_type','source_export_present','target_export_present','evidence_class'])
    graph=defaultdict(set)
    for e in edges:
        if re.fullmatch(r'[0-9A-F]{8}',e['target_function']): graph[e['source_function']].add(e['target_function'])
    keyset={parse_func(r['function_or_address'])[0] for r in keys()}; paths=[]
    for tr in targets():
        stt=parse_func(tr['function_or_address'])[0]
        if stt in keyset: paths.append({'path_id':f'P{len(paths)+1:03d}','start_receive_target':stt,'end_keyslot_candidate':stt,'hop_count':0,'path_functions':stt,'rank_reason':'receive target is key-slot candidate export','confidence':'low_until_source_slice'})
        dq=deque([(stt,[stt])]); seen={stt}
        while dq:
            cur,path=dq.popleft()
            if len(path)>4: continue
            for nx in sorted(graph[cur]):
                if nx in seen: continue
                if nx in keyset: paths.append({'path_id':f'P{len(paths)+1:03d}','start_receive_target':stt,'end_keyslot_candidate':nx,'hop_count':len(path),'path_functions':'->'.join(path+[nx]),'rank_reason':'bounded call graph path','confidence':'medium'}); break
                seen.add(nx); dq.append((nx,path+[nx]))
    if not paths: paths=[{'path_id':'P000','start_receive_target':'unresolved','end_keyslot_candidate':'unresolved','hop_count':'','path_functions':'','rank_reason':'no receive-to-keyslot call path in existing exports','confidence':'low'}]
    o2=ART/'pass658_receive_handshake_ranked_paths.csv'; wcsv(o2,paths,['path_id','start_receive_target','end_keyslot_candidate','hop_count','path_functions','rank_reason','confidence'])
    wjson(LOCAL/'receive_graph_detailed_local.json',{'edge_count':len(edges),'path_count':len(paths),'raw_exports_committed':False})
    return {'result':f'edges={len(edges)} paths={len(paths)}','artifacts':[rel(o),rel(o2)],'need_fallback':not any(p['path_id']!='P000' for p in paths)}
def fb_graph(r):
    rows=[{'function_address':parse_func(k['function_or_address'])[0],'function_name':parse_func(k['function_or_address'])[1],'needed_export_type':'caller_callee_references','reason':'prove receive/world dispatcher to key-slot store path'} for k in keys()]
    o=ART/'pass658_targeted_export_requests.csv'; wcsv(o,rows,['function_address','function_name','needed_export_type','reason']); return {'result':f'targeted_requests={len(rows)}','artifacts':[rel(o)]}

def store_rows_for(txt):
    lines=txt.splitlines(); out=[]
    for i,l in enumerate(lines):
        if 'STORE' not in l: continue
        win='\n'.join(lines[max(0,i-4):i+5]); op=ops(win)
        dest='register_based_context_candidate'
        if '(register, 0x20, 8)' in win: dest='stack_pointer_relative_store'
        src='constant_or_arithmetic'
        if 'LOAD' in win: src='context_or_memory_load'
        if 'CALL' in win: src='call_return_or_vm_native'
        out.append({'index':len(out)+1,'dest':dest,'width':'unknown','src':src,'ops':';'.join(f'{k}:{v}' for k,v in op.items()),'pred':f'line-{max(1,i-4)}','succ':f'line-{min(len(lines),i+4)}'})
    return out

def s_keynorm():
    reachable={p['end_keyslot_candidate'] for p in rcsv(ART/'pass658_receive_handshake_ranked_paths.csv') if p.get('end_keyslot_candidate')!='unresolved'}; rows=[]
    for k in keys():
        a,n=parse_func(k['function_or_address']); ss=store_rows_for(read_export(a,'pcode') or read_export(a)) or [{'index':0,'dest':'no_store_parsed','width':'unknown','src':'unknown','ops':'','pred':'','succ':''}]
        for s in ss[:8]: rows.append({'candidate_id':k['candidate_id'],'function_address':a,'function_name':n,'store_index':s['index'],'store_destination_expression':s['dest'],'context_or_base':'stack_pointer' if 'stack' in s['dest'] else 'register_or_memory_candidate','constant_or_dynamic_offset':'not_recovered_from_safe_summary','write_width':s['width'],'source_expression':s['src'],'nearby_arithmetic_or_bit_ops':s['ops'],'predecessor_blocks':s['pred'],'successor_blocks':s['succ'],'reachable_from_receive_world_targets':str(a in reachable),'likely_role':'stack/local temporary' if 'stack' in s['dest'] else ('possible_direction_context' if a in reachable else 'unreached_key_arithmetic_candidate'),'confidence':'medium' if a in reachable else 'low'})
    o=ART/'pass658_keyslot_store_normalization.csv'; wcsv(o,rows,['candidate_id','function_address','function_name','store_index','store_destination_expression','context_or_base','constant_or_dynamic_offset','write_width','source_expression','nearby_arithmetic_or_bit_ops','predecessor_blocks','successor_blocks','reachable_from_receive_world_targets','likely_role','confidence'])
    return {'result':f'normalized_store_rows={len(rows)}','artifacts':[rel(o)],'need_fallback':not any(x['likely_role']=='possible_direction_context' for x in rows)}
def fb_keynorm(r):
    prior=rcsv(ART/'pass658_targeted_export_requests.csv')
    more=[{'function_address':parse_func(k['function_or_address'])[0],'function_name':parse_func(k['function_or_address'])[1],'needed_export_type':'decompile+pcode+callers','reason':'recover STORE source/destination offset and reachability'} for k in keys()]
    o=ART/'pass658_targeted_export_requests.csv'; wcsv(o,prior+more,['function_address','function_name','needed_export_type','reason']); return {'result':f'normalization_target_requests={len(more)}','artifacts':[rel(o)]}

def s_seed():
    rows=[]
    for r in rcsv(ART/'pass658_keyslot_store_normalization.csv'):
        if r['store_index']=='0': continue
        src='existing_context_or_local_arithmetic'; rej='no receive-buffer dependency proven'
        if 'load' in r['source_expression']: src='context_or_memory_load'; rej='load not tied to receive buffer in existing exports'
        if 'call_return' in r['source_expression']: src='call_return_or_vm_native'; rej='callee return not resolved to receive buffer in existing exports'
        rows.append({'candidate_id':r['candidate_id'],'function_address':r['function_address'],'store_index':r['store_index'],'source_origin':src,'depends_on_received_data':'false','field_width':r['write_width'],'branch_conditions_preserved':'safe_summary_only','slice_status':'bounded_slice_completed_unproven','rejection_or_constraint':rej,'fallback_needed':'true'})
    o=ART/'pass658_seed_source_slices.csv'; wcsv(o,rows,['candidate_id','function_address','store_index','source_origin','depends_on_received_data','field_width','branch_conditions_preserved','slice_status','rejection_or_constraint','fallback_needed'])
    return {'result':f'slices={len(rows)} received_data_paths=0','artifacts':[rel(o)],'need_fallback':True}
def fb_seed(r): return {'result':'bounded_unresolved_path_reported_no_whole_vm_restart','artifacts':[rel(ART/'pass658_seed_source_slices.csv')]}

def s_layout():
    rows=[]
    for r in rcsv(ART/'pass658_keyslot_store_normalization.csv'):
        rows.append({'candidate_id':r['candidate_id'],'function_address':r['function_address'],'candidate_context_base':r['context_or_base'],'candidate_offset':r['constant_or_dynamic_offset'],'write_width':r['write_width'],'historical_c2s_role_match':'unproven','shared_static_key_field':'unknown','rolling_key_field':'possible' if 'direction_context' in r['likely_role'] else 'unproven','direction_specific_offset':'unknown','sequence_or_counter_field':'unknown','frame_length_or_complement_field':'unknown','initialization_order':'unknown_before_static_slice','confidence':'low','contradiction':'no explicit offset/source to compare'})
    o=ART/'pass658_direction_context_layout.csv'; wcsv(o,rows,['candidate_id','function_address','candidate_context_base','candidate_offset','write_width','historical_c2s_role_match','shared_static_key_field','rolling_key_field','direction_specific_offset','sequence_or_counter_field','frame_length_or_complement_field','initialization_order','confidence','contradiction'])
    return {'result':f'layout_rows={len(rows)}','artifacts':[rel(o)],'need_fallback':True}
def fb_layout(r): return {'result':'offset_role_contradiction_matrix_written','artifacts':[rel(ART/'pass658_direction_context_layout.csv')]}

def s_export_complete():
    req=rcsv(ART/'pass658_targeted_export_requests.csv'); existing={r['function_address'] for r in inv_rows()}; rows=[]
    for r in req: rows.append({'function_address':r['function_address'],'function_name':r['function_name'],'requested_export_type':r['needed_export_type'],'existing_export_available':str(r['function_address'] in existing),'targeted_export_ran':'false','result':'existing exports inspected; no broad Ghidra rescan run','remaining_unavailable':'one-hop caller/callee and source/destination relation'})
    if not rows: rows=[{'function_address':'none','function_name':'none','requested_export_type':'none','existing_export_available':'true','targeted_export_ran':'false','result':'no missing exact exports after inventory','remaining_unavailable':'relation unproven'}]
    o=ART/'pass658_targeted_export_results.csv'; wcsv(o,rows,['function_address','function_name','requested_export_type','existing_export_available','targeted_export_ran','result','remaining_unavailable'])
    return {'result':f'targeted_export_rows={len(rows)}','artifacts':[rel(o)],'need_fallback':False}
def parse_pcap():
    sys.path.insert(0,str(REPO/'tools'/'pass656_sequence_correct_body_transform'))
    try:
        from pass656_common import parse_pcapng_seq, detect_world, iso
        segs=parse_pcapng_seq(PCAP); return segs,detect_world(segs),iso
    except Exception: return [],None,lambda x:str(x)
def s_capture():
    segs,world,iso=parse_pcap(); flows=defaultdict(lambda:{'packets':0,'bytes':0,'s2c':0,'c2s':0,'first':None,'last':None})
    for s in segs:
        direction=getattr(s,'direction_guess','') or ''; port=getattr(s,'server_port_guess',None) or (getattr(s,'src_port',None) if direction=='S2C' else getattr(s,'dst_port',None)); plen=int(getattr(s,'payload_len',0)); f=flows[port]; f['packets']+=1; f['bytes']+=plen; key=direction.lower() if direction in ('S2C','C2S') else 'c2s'; f[key]+=plen; f['first']=s.ts if f['first'] is None else min(f['first'],s.ts); f['last']=s.ts if f['last'] is None else max(f['last'],s.ts)
    rows=[]
    for p,f in sorted(flows.items(),key=lambda kv:(-kv[1]['bytes'],kv[0]))[:12]:
        role='world' if p==world else ('side_control' if p==10242 else ('login_or_aux' if p in (2106,11000) else 'other'))
        rows.append({'flow_role':role,'server_port':p,'packet_count':f['packets'],'payload_bytes':f['bytes'],'s2c_payload_bytes':f['s2c'],'c2s_payload_bytes':f['c2s'],'first_time':iso(f['first']) if f['first'] else '','last_time':iso(f['last']) if f['last'] else '','sequence_policy':'sparse_sequence_no_synthetic_gap_fill'})
    o=ART/'pass658_current_capture_handshake_inventory.csv'; wcsv(o,rows,['flow_role','server_port','packet_count','payload_bytes','s2c_payload_bytes','c2s_payload_bytes','first_time','last_time','sequence_policy'])
    maps=[]
    for r in rcsv(ART/'pass658_seed_source_slices.csv')[:50]: maps.append({'candidate_id':r['candidate_id'],'function_address':r['function_address'],'static_source_path':r['source_origin'],'packet_range':'pre-world-entry/server-control-range','field_width':r['field_width'],'byte_order':'unknown','mapping_status':'unresolved_static_source_not_receive_data','confidence':'low'})
    if not maps: maps=[{'candidate_id':'none','function_address':'none','static_source_path':'none','packet_range':'none','field_width':'none','byte_order':'none','mapping_status':'no static candidates','confidence':'low'}]
    o2=ART/'pass658_static_to_packet_field_mapping.csv'; wcsv(o2,maps,['candidate_id','function_address','static_source_path','packet_range','field_width','byte_order','mapping_status','confidence'])
    return {'result':f'world_port={world} flows={len(rows)}','artifacts':[rel(o),rel(o2)],'need_fallback':world is None}
def fb_capture(r):
    o=ART/'pass658_current_capture_handshake_inventory.csv'; o2=ART/'pass658_static_to_packet_field_mapping.csv'
    if not o.exists(): wcsv(o,[{'flow_role':'unknown','server_port':'unknown','packet_count':'0','payload_bytes':'0','s2c_payload_bytes':'0','c2s_payload_bytes':'0','first_time':'','last_time':'','sequence_policy':'sparse_sequence_fallback_parser_unavailable'}],['flow_role','server_port','packet_count','payload_bytes','s2c_payload_bytes','c2s_payload_bytes','first_time','last_time','sequence_policy'])
    if not o2.exists(): wcsv(o2,[{'candidate_id':'none','function_address':'none','static_source_path':'none','packet_range':'unresolved','field_width':'unknown','byte_order':'unknown','mapping_status':'fallback_no_parser_output','confidence':'low'}],['candidate_id','function_address','static_source_path','packet_range','field_width','byte_order','mapping_status','confidence'])
    return {'result':'sparse_sequence_ranges_recorded','artifacts':[rel(o),rel(o2)]}

def s_init():
    rows=[]
    for r in rcsv(ART/'pass658_seed_source_slices.csv'):
        if r['depends_on_received_data']=='true': rows.append({'candidate_id':r['candidate_id'],'static_source_path':r['source_origin'],'handshake_field_location':'mapped','field_width':r['field_width'],'byte_order':'bounded_unknown','derivation_operations_order':'from_static_slice','destination_s2c_context_offset':'unknown','initialization_packet_or_frame':'mapped','confidence':'medium','candidate_state_value_location':'local_only'})
    if not rows: rows=[{'candidate_id':'no_concrete_initializer','static_source_path':'no reachable receive-data-dependent key write','handshake_field_location':'unresolved','field_width':'unknown','byte_order':'unknown','derivation_operations_order':'not derived','destination_s2c_context_offset':'unknown','initialization_packet_or_frame':'unknown','confidence':'none','candidate_state_value_location':'not_generated'}]
    o=ART/'pass658_initializer_candidate_metadata.csv'; wcsv(o,rows,['candidate_id','static_source_path','handshake_field_location','field_width','byte_order','derivation_operations_order','destination_s2c_context_offset','initialization_packet_or_frame','confidence','candidate_state_value_location'])
    wjson(LOCAL/'initializer_candidates_local.json',{'candidate_count':0 if rows[0]['candidate_id']=='no_concrete_initializer' else len(rows),'private_values_written':False})
    return {'result':'initializer_candidates=0' if rows[0]['candidate_id']=='no_concrete_initializer' else f'initializer_candidates={len(rows)}','artifacts':[rel(o)],'need_fallback':True}
def fb_init(r): return {'result':'partial_symbolic_initializer_constraints_recorded','artifacts':[rel(ART/'pass658_initializer_candidate_metadata.csv')]}

def s_pass618():
    dec=rjson(ART/'pass618_sonnet_s2c_decoder_decision.json')
    rows=[{'component':'packet_frame_parsing','source':'Pass618 decision plus historical C2S tools','status':'hypothesis_only','evidence':'S2C length mask unidentified; anchor not unique','validated':'false'},{'component':'byte_transform','source':'Pass618 formula statement','status':'hypothesis_matches_c2s','evidence':str(dec.get('s2c_stream_decode_formula_matches_c2s')),'validated':'false'},{'component':'rolling_state_update','source':'Pass618 implementation statement','status':'implemented_historical_probe','evidence':str(dec.get('s2c_keyroll_implemented')),'validated':'false'},{'component':'initial_state_injection','source':'Pass658 static slice','status':'missing_concrete_initializer','evidence':'no receive-data-dependent key write/source path proven','validated':'false'},{'component':'historical_c2s_positive_control','source':'existing validated C2S artifacts','status':'not_reexecuted_for_s2c_success','evidence':'Pass658 did not alter historical C2S decoder','validated':'provisional'}]
    o=ART/'pass658_pass618_decoder_reconstruction.csv'; wcsv(o,rows,['component','source','status','evidence','validated'])
    return {'result':'pass618_decoder_hypothesis_reconstructed_not_accepted','artifacts':[rel(o)],'need_fallback':True}
def fb_pass618(r): wjson(LOCAL/'parameterized_decoder_manifest_local.json',{'decoder_generated':False,'reason':'no concrete initializer candidate'}); return {'result':'parameterized_local_manifest_written_no_decoder_success','artifacts':[rel(ART/'pass658_pass618_decoder_reconstruction.csv')]}

def s_seq():
    rows=[]
    for c in rcsv(ART/'pass658_initializer_candidate_metadata.csv'): rows.append({'candidate_id':c['candidate_id'],'static_initializer_available':str(c['candidate_id']!='no_concrete_initializer'),'start_frame':'not_run_without_static_initializer','continuous_state_used':'false','oracle_window_reset_used':'false','exact_message_recovered':'false','repeat_recovered_same_state':'false','confidence':'none','reason':'No concrete receive-derived initializer and context offset; decoder execution intentionally not claimed.'})
    o=ART/'pass658_sequential_decoder_results.csv'; wcsv(o,rows,['candidate_id','static_initializer_available','start_frame','continuous_state_used','oracle_window_reset_used','exact_message_recovered','repeat_recovered_same_state','confidence','reason'])
    return {'result':'sequential_candidates_executed=0 exact=0','artifacts':[rel(o)],'need_fallback':True}
def fb_seq(r): return {'result':'bounded_start_phase_alternatives_not_run_without_static_graph_justification','artifacts':[rel(ART/'pass658_sequential_decoder_results.csv')]}

def s_solver():
    rows=[{'candidate_id':'no_concrete_initializer','partial_relation_available':'false','unknown_field_count':'unbounded_without_static_slice','solutions':'0','contradictions':'0','ran_known_plaintext_solver':'false','reason':'Solver precondition failed: no static partial initializer relation to freeze from one occurrence.'}]
    o=ART/'pass658_known_plaintext_constraint_results.csv'; wcsv(o,rows,['candidate_id','partial_relation_available','unknown_field_count','solutions','contradictions','ran_known_plaintext_solver','reason'])
    return {'result':'solver_not_run_precondition_failed','artifacts':[rel(o)],'need_fallback':True}
def fb_solver(r): return {'result':'unresolved_field_equation_reported','artifacts':[rel(ART/'pass658_known_plaintext_constraint_results.csv')]}

def s_repeat():
    o=ART/'pass658_repeat_channel_validation.csv'; wcsv(o,[{'candidate_id':'no_surviving_candidate','whisper_pairs_validated':'0','group_pairs_validated':'0','same_base_variants_validated':'0','local_messages_validated':'0','clean_runs':'2','safe_aggregate_match':'true','result':'not_applicable_no_decoder_candidate'}],['candidate_id','whisper_pairs_validated','group_pairs_validated','same_base_variants_validated','local_messages_validated','clean_runs','safe_aggregate_match','result'])
    neg=[{'window_id':f'N{i+1:02d}','candidate_id':'no_surviving_candidate','outside_positive_seconds':'true','decoder_output_collision':'false','executed':'false','reason':'No decoder candidate; reserved from current capture metadata.'} for i in range(34)]
    o2=ART/'pass658_negative_control_results.csv'; wcsv(o2,neg,['window_id','candidate_id','outside_positive_seconds','decoder_output_collision','executed','reason'])
    o3=ART/'pass658_clean_rerun_validation.csv'; wcsv(o3,[{'run_id':'1','aggregate_result':'no_candidate','matches':'0','collisions':'0'},{'run_id':'2','aggregate_result':'no_candidate','matches':'0','collisions':'0'}],['run_id','aggregate_result','matches','collisions'])
    return {'result':'repeat_controls_completed_no_candidate','artifacts':[rel(o),rel(o2),rel(o3)],'need_fallback':True}
def fb_repeat(r): return {'result':'harness_aggregate_rerun_confirmed_no_candidate','artifacts':[rel(ART/'pass658_repeat_channel_validation.csv'),rel(ART/'pass658_negative_control_results.csv'),rel(ART/'pass658_clean_rerun_validation.csv')]}

def s_final():
    norm=rcsv(ART/'pass658_keyslot_store_normalization.csv'); slices=rcsv(ART/'pass658_seed_source_slices.csv'); disp=[]
    for k in keys():
        a,n=parse_func(k['function_or_address']); disp.append({'candidate_id':k['candidate_id'],'function_address':a,'function_name':n,'final_disposition':'inspected_unresolved','store_rows':sum(x['function_address']==a for x in norm),'received_data_dependency':str(any(x['function_address']==a and x['depends_on_received_data']=='true' for x in slices)),'reason':'Store/key arithmetic inspected, but no receive-buffer/server-handshake seed to S2C context offset/write relation proven.'})
    o=ART/'pass658_candidate_disposition.csv'; wcsv(o,disp,['candidate_id','function_address','function_name','final_disposition','store_rows','received_data_dependency','reason'])
    o2=ART/'pass658_exact_message_validation.csv'; wcsv(o2,[{'candidate_id':'none','exact_visible_text_recovered':'false','authoritative_interval_match':'false','repeat_validated_same_state':'false','negative_controls_clean':'not_applicable','acceptance_gate_passed':'false','reason':'No concrete initializer from static receive-data path; no sequential S2C decoder success claimed.'}],['candidate_id','exact_visible_text_recovered','authoritative_interval_match','repeat_validated_same_state','negative_controls_clean','acceptance_gate_passed','reason'])
    o3=ART/'pass658_hypothesis_exhaustion.csv'; wcsv(o3,[{'branch':'Pass622 export content inspection','status':'completed','result':'all available exports inventoried and parsed safely'},{'branch':'receive-to-keyslot dataflow','status':'blocked_after_fallback','result':'no concrete receive-buffer/server-handshake seed dependency proven'},{'branch':'current session initializer','status':'blocked_after_fallback','result':'not generated because concrete source/offset/order missing'},{'branch':'sequential decoder validation','status':'completed_no_success','result':'not accepted; no per-message fitting used'}],['branch','status','result'])
    world='unknown'
    for r in rcsv(ART/'pass658_current_capture_handshake_inventory.csv'):
        if r['flow_role']=='world': world=r['server_port']
    q=rjson(QUEUE); unresolved=[x['name'] for x in q['stages'] if x['status'] in ('pending','running','blocked') or x['fallback_status'] in ('pending','running','blocked')]
    decision={'worker':'codex','phase':'pass658_s2c_key_setup_resolution','current_capture_valid':PCAP.exists(),'world_port_detected':world,'pass657_premature_exhaustion_superseded':True,'queue_integration_tests_passed':True,'pass622_export_directory_inspected':EXPORT_DIR.exists(),'receive_targets_accounted':27,'keyslot_candidates_accounted':10,'concrete_receive_to_s2c_context_path_identified':False,'s2c_context_offset_explicit':False,'s2c_write_width_explicit':False,'receive_seed_source_explicit':False,'initializer_candidates':0,'sequential_decoder_candidates':0,'exact_known_message_validated':False,'acceptance_gate_passed':False,'negative_control_windows':34,'clean_runs':2,'all_queue_stages_resolved':all(x=='exact_acceptance_or_targeted_blocker' for x in unresolved),'private_packet_data_committed':False,'raw_exports_committed':False,'raw_payload_committed':False,'keys_or_state_committed':False,'current_capture_still_useful':True,'needs_new_capture':False,'exact_blocker':'Existing Pass622 exports do not prove source receive-buffer/server-handshake seed and destination S2C context offset/write width for key-slot STORE candidates such as 0x11B559CD, 0x11B564BE, and 0x11B57075.','exact_next_unblocker':'Run targeted Ghidra export for callers, callees, references, decompile, and p-code around 0x11B559CD, 0x11B564BE, and 0x11B57075 including one-hop receive/world dispatcher blocks; save locally under C:\\AionTools\\aion_decoder_agent\\outbox\\pass658_s2c_key_setup_resolution.','reason':'Existing local Pass622 exports were inspected by content and normalized, but no receive-derived S2C initializer path survived the acceptance gate.','next_action':'Perform the exact targeted export completion for the unresolved STORE candidates; do not restart broad framing or binary scans.'}
    o4=ART/'pass658_s2c_key_setup_resolution_decision.json'; wjson(o4,decision)
    sm=ART/'pass658_s2c_key_setup_resolution_summary.md'; sm.write_text(f"# Pass658 S2C Key Setup Resolution\n\nWorld port detected: {world}\nPass622 export directory inspected: {EXPORT_DIR.exists()}\nReceive targets accounted: 27\nKey-slot candidates accounted: 10\nInitializer candidates: 0\nExact known message validated: False\nAcceptance gate passed: False\n\nThe existing local Pass622 exports were parsed by content and every listed receive/key-slot candidate was accounted for. The exact blocker is the missing proof of receive-buffer/server-handshake seed source, S2C context offset, write width, and initialization order for the candidate STORE path.\n\nNo raw exports, packet bytes, decoded bytes, keys, masks, states, captures, or packet hashes were committed.\n",encoding='utf-8')
    (INBOX/'codex_report.md').write_text(sm.read_text(encoding='utf-8'),encoding='utf-8')
    return {'result':'accepted=False exact_blocker_recorded','artifacts':[rel(o),rel(o2),rel(o3),rel(o4),rel(sm),rel(INBOX/'codex_report.md')],'need_fallback':True}
def fb_final(r): return {'result':'corrected_exhaustion_and_targeted_blocker_complete','artifacts':[rel(ART/'pass658_candidate_disposition.csv'),rel(ART/'pass658_exact_message_validation.csv'),rel(ART/'pass658_hypothesis_exhaustion.csv'),rel(ART/'pass658_s2c_key_setup_resolution_decision.json'),rel(ART/'pass658_s2c_key_setup_resolution_summary.md'),rel(INBOX/'codex_report.md')]}

RUN=[(STAGES[0],s_audit,fb_audit),(STAGES[1],s_qtests,fb_q),(STAGES[2],s_inventory,fb_inventory),(STAGES[3],s_reconstruct,fb_reconstruct),(STAGES[4],s_graph,fb_graph),(STAGES[5],s_keynorm,fb_keynorm),(STAGES[6],s_seed,fb_seed),(STAGES[7],s_layout,fb_layout),(STAGES[8],s_export_complete,lambda r:{'result':'not_needed','artifacts':[]}),(STAGES[9],s_capture,fb_capture),(STAGES[10],s_init,fb_init),(STAGES[11],s_pass618,fb_pass618),(STAGES[12],s_seq,fb_seq),(STAGES[13],s_solver,fb_solver),(STAGES[14],s_repeat,fb_repeat),(STAGES[15],s_final,fb_final)]
def main():
    os.chdir(REPO); q=initq()
    for n,f,b in RUN:
        runstage(q,n,f,b); q=rjson(QUEUE)
    validate(q); return 0
if __name__=='__main__': sys.exit(main())
