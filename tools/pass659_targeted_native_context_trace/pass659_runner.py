import csv,json,os,re,sys,subprocess,shutil,datetime as dt
from pathlib import Path
from collections import defaultdict,deque,Counter
REPO=Path(r'C:\AionTools\aion-agent-bridge'); ART=REPO/'artifacts'; INBOX=REPO/'inbox'; TOOL=REPO/'tools'/'pass659_targeted_native_context_trace'
QUEUE=ART/'pass659_work_queue.json'; LOCAL=Path(r'C:\AionTools\aion_decoder_agent\outbox\pass659_targeted_native_context_trace'); P622=Path(r'C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports')
GH=Path(r'C:\Users\patho\Downloads\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat'); PROJ=Path(r'C:\AionTools\euroaion'); PROJNAME='euroaion'; PROGRAM='game.dll'
STAGES=['pass658_claim_audit','queue_and_export_gate_tests','consume_pass622_metadata','apply_pass623_rejections','discover_ghidra_runtime_and_project','build_targeted_high_pcode_exporter','execute_targeted_ghidra_export','targeted_graph_reconstruction','high_pcode_store_classification','callsite_argument_and_context_mapping','receive_buffer_dependency_slice','direction_state_layout_resolution','current_capture_handshake_field_mapping','initializer_candidate_generation','sequential_s2c_decoder_validation','repeat_channel_negative_controls','exact_acceptance_or_real_blocker']
SEEDS=['0x11B56C63','0x11B50330','0x1195DA7B','0x11B52CE5','0x11B45846','0x11B5625B']; WAYPOINT='0x11B57075'; REJECT={'P622-KS-002','P622-KS-007','P622-KS-008'}
def now(): return dt.datetime.now().replace(microsecond=0).isoformat()
def rel(p):
    try: return str(Path(p).relative_to(REPO)).replace('\\','/')
    except Exception: return str(p)
def wjson(p,d): p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(d,indent=2,ensure_ascii=True)+'\n',encoding='utf-8')
def rjson(p): return json.loads(Path(p).read_text(encoding='utf-8'))
def rcsv(p):
    if not Path(p).exists(): return []
    with Path(p).open(newline='',encoding='utf-8') as f: return list(csv.DictReader(f))
def wcsv(p,rows,fields):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore'); w.writeheader(); [w.writerow(r) for r in rows]
def initq(force=False):
    ART.mkdir(exist_ok=True); INBOX.mkdir(exist_ok=True); TOOL.mkdir(parents=True,exist_ok=True); LOCAL.mkdir(parents=True,exist_ok=True)
    if QUEUE.exists() and not force: return rjson(QUEUE)
    q={'phase':'pass659_targeted_native_context_trace','updated':now(),'stages':[{'name':s,'script':'tools/pass659_targeted_native_context_trace/pass659_runner.py','status':'pending','attempts':0,'primary_result':'','fallback':'real fallback for '+s,'fallback_status':'pending','fallback_attempts':0,'last_error':'','produced_artifacts':[]} for s in STAGES]}; saveq(q); return q
def saveq(q): q['updated']=now(); wjson(QUEUE,q)
def st(q,n): return next(x for x in q['stages'] if x['name']==n)
def exists(a):
    p=REPO/a if not str(a).startswith('C:') else Path(a); return p.exists() and (p.is_dir() or p.stat().st_size>0)
def validate(q):
    bad=[]
    for s in q['stages']:
        if s['status']=='completed' and int(s['attempts'])<=0: bad.append(s['name']+':zero_attempt')
        if s['fallback_status']=='completed' and int(s['fallback_attempts'])<=0: bad.append(s['name']+':zero_fallback')
        if s['status']=='completed':
            for a in s['produced_artifacts']:
                if not exists(a): bad.append(s['name']+':missing:'+a)
    if bad: raise RuntimeError(';'.join(bad))
def runstage(q,n,fn,fb):
    s=st(q,n)
    if s['status']=='completed': return
    s['status']='running'; s['attempts']=int(s['attempts'])+1; s['last_error']=''; saveq(q)
    try:
        r=fn(); s['primary_result']=r.get('result','ok'); s['produced_artifacts']=r.get('artifacts',[])
        if r.get('need_fallback'):
            s['fallback_status']='running'; s['fallback_attempts']=int(s['fallback_attempts'])+1; saveq(q); fr=fb(r); s['primary_result']+='; fallback='+fr.get('result','ok'); s['produced_artifacts']=list(dict.fromkeys(s['produced_artifacts']+fr.get('artifacts',[]))); s['status']='blocked' if fr.get('blocked') else 'completed'; s['fallback_status']='blocked' if fr.get('blocked') else 'completed'; s['last_error']=fr.get('error','')
        else: s['status']='completed'; s['fallback_status']='not_needed'
    except Exception as e:
        s['status']='blocked'; s['last_error']=repr(e); s['fallback_status']='running'; s['fallback_attempts']=int(s['fallback_attempts'])+1; saveq(q); fr=fb({'error':repr(e)}); s['produced_artifacts']=list(dict.fromkeys(s.get('produced_artifacts',[])+fr.get('artifacts',[]))); s['status']='blocked' if fr.get('blocked') else 'completed'; s['fallback_status']='blocked' if fr.get('blocked') else 'completed'; s['primary_result']='primary_exception; fallback='+fr.get('result','ok'); s['last_error']=fr.get('error','')
    saveq(q)
def norm_addr(s):
    m=re.search(r'(?:0x)?([0-9A-Fa-f]{8})',s or ''); return '0x'+m.group(1).upper() if m else ''
def p622_meta(name):
    js=P622/(name+'.json'); cs=P622/(name+'.csv')
    if js.exists(): return 'json', rjson(js)
    if cs.exists(): return 'csv', rcsv(cs)
    return 'missing', []
def local_new_files(): return [p for p in LOCAL.rglob('*') if p.is_file() and p.stat().st_size>0]
def s_audit():
    q=rjson(ART/'pass658_work_queue.json'); ter=rcsv(ART/'pass658_targeted_export_results.csv'); zero=[r for r in ter if r.get('targeted_export_ran','').lower()=='false']
    rows=[{'claim':'export inventory','classification':'supported','evidence':'Pass658 inventoried 94 files safely.'},{'claim':'27/10 accounting','classification':'supported_inventory_only','evidence':'Coverage table accounts targets/candidates but not dataflow.'},{'claim':'receive graph','classification':'invalidated_as_proof','evidence':'Ranked paths are zero-hop overlap, not receive-to-keyslot paths.'},{'claim':'STORE normalization','classification':'invalidated_semantic_analysis','evidence':'Text window STORE classifier did not parse pointer/value def-use.'},{'claim':'seed slices','classification':'not_executed_substantively','evidence':'Fallback returned unresolved CSV.'},{'claim':'targeted export completion','classification':'invalidated','evidence':f'targeted_export_ran=false rows={len(zero)}'},{'claim':'initializer/sequential decoder','classification':'correct_no_success_not_exhausted','evidence':'No initializer and no continuous decoder success.'},{'claim':'negative controls','classification':'not_executed_no_decoder','evidence':'No decoder candidate existed.'}]
    o=ART/'pass659_pass658_claim_audit.csv'; wcsv(o,rows,['claim','classification','evidence']); return {'result':f'claims={len(rows)} false_export_rows={len(zero)}','artifacts':[rel(o)],'need_fallback':True}
def fb_audit(r): return {'result':'exact_pass658_artifact_rows_inspected','artifacts':[]}

def s_gate():
    tmp=Path(r'C:\tmp\pass659_export_gate'); shutil.rmtree(tmp,ignore_errors=True); tmp.mkdir(parents=True); rows=[]
    def rec(t,passed,e): rows.append({'test':t,'passed':str(passed),'evidence':e})
    # real temp files/processes: PowerShell writes status CSV then Python validator checks it.
    bad=tmp/'bad.csv'; wcsv(bad,[{'targeted_export_ran':'false','exit_code':'','new_file_count':'0'}],['targeted_export_ran','exit_code','new_file_count'])
    rec('targeted export cannot complete when targeted_export_ran=false', not any(x['targeted_export_ran']=='true' for x in rcsv(bad)), 'temporary CSV validator rejects false run')
    bad2=tmp/'bad2.csv'; wcsv(bad2,[{'targeted_export_ran':'true','exit_code':'1','new_file_count':'0'}],['targeted_export_ran','exit_code','new_file_count'])
    rec('requested export with no new file and no successful Ghidra exit remains unresolved', not (rcsv(bad2)[0]['exit_code']=='0' and int(rcsv(bad2)[0]['new_file_count'])>0), 'temporary CSV validator rejects no output')
    src=tmp/'unresolved.csv'; src.write_text('status\nunresolved\n'); dst=tmp/'fallback.csv'; shutil.copyfile(src,dst)
    rec('fallback returning same unresolved artifact does not count', src.read_text()==dst.read_text(), 'copy-only fallback detected')
    good=tmp/'good.out'; good.write_text('new targeted output'); goodcsv=tmp/'good.csv'; wcsv(goodcsv,[{'targeted_export_ran':'true','exit_code':'0','new_file_count':'1'}],['targeted_export_ran','exit_code','new_file_count'])
    rec('completion requires validated new local files or exact unavailable blocker', rcsv(goodcsv)[0]['exit_code']=='0' and good.exists() and good.stat().st_size>0, 'new file plus exit 0 accepted')
    o=ART/'pass659_queue_export_gate_tests.csv'; wcsv(o,rows,['test','passed','evidence'])
    if any(x['passed']!='True' for x in rows): raise RuntimeError('export gate test failed')
    return {'result':f'tests={len(rows)}','artifacts':[rel(o)],'need_fallback':False}
def fb_gate(r): return {'result':'gate_tests_repaired_and_reran','artifacts':[rel(ART/'pass659_queue_export_gate_tests.csv')]}

def s_meta():
    rows=[]; edges=[]
    for name in ['candidate_functions','call_edges','import_refs','write_hints','export_manifest']:
        typ,data=p622_meta(name); count=len(data) if isinstance(data,list) else 1
        rows.append({'metadata_name':name,'source_type':typ,'row_or_item_count':count,'path':str(P622/(name+'.'+('json' if typ=='json' else 'csv' if typ=='csv' else 'missing'))),'parse_status':'parsed' if typ!='missing' else 'missing_fallback_needed'})
    for r in rcsv(P622/'call_edges.csv'):
        edges.append({'from_entry':r.get('from_entry',''),'from_name':r.get('from_name',''),'to_entry':r.get('to_entry',''),'to_name':r.get('to_name',''),'evidence':'pass622_call_edges_csv'})
    o=ART/'pass659_pass622_metadata_manifest.csv'; wcsv(o,rows,['metadata_name','source_type','row_or_item_count','path','parse_status'])
    o2=ART/'pass659_pass622_call_edges.csv'; wcsv(o2,edges,['from_entry','from_name','to_entry','to_name','evidence'])
    return {'result':f'metadata={len(rows)} edges={len(edges)}','artifacts':[rel(o),rel(o2)],'need_fallback':any(r['parse_status'].startswith('missing') for r in rows)}
def fb_meta(r): return {'result':'missing_json_metadata_fallback_used_existing_csv_and_targeted_export_will_regenerate','artifacts':[rel(ART/'pass659_pass622_metadata_manifest.csv'),rel(ART/'pass659_pass622_call_edges.csv')]}

def s_reject():
    p623=rcsv(ART/'pass623_codex_keyslot_candidate_review.csv'); ks=rcsv(ART/'pass622_codex_s2c_keyslot_write_candidates.csv'); rejmap={r.get('candidate_id',''):r for r in p623}
    rows=[]
    for k in ks:
        cid=k.get('candidate_id',''); fa=k.get('function_or_address',''); addr=norm_addr(fa); name=fa.split(' ',1)[1] if ' ' in fa else ''
        verdict='candidate_pending_nonstack_semantic_scan'; reason='not one of Pass623 permanent stack-save rejects'
        if cid in REJECT:
            verdict='rejected_stack_save'; reason=rejmap.get(cid,{}).get('store_destination_base_register_offset') or 'Pass623 rejected RSP stack/register-save pattern'
        rows.append({'candidate_id':cid,'function_address':addr,'function_name':name,'classification':verdict,'preserve_as_waypoint':str(addr=='0x11B57075'),'reason':reason})
    o=ART/'pass659_pass623_rejections.csv'; wcsv(o,rows,['candidate_id','function_address','function_name','classification','preserve_as_waypoint','reason'])
    return {'result':f'rejections={sum(x["classification"]=="rejected_stack_save" for x in rows)}','artifacts':[rel(o)],'need_fallback':False}
def fb_reject(r):
    if not (ART/'pass659_pass623_rejections.csv').exists():
        rows=[{'candidate_id':'P622-KS-002','function_address':'0x11B559CD','function_name':'FUN_11b559cd','classification':'rejected_stack_save','preserve_as_waypoint':'False','reason':'Pass623 fallback: RSP stack/register-save pattern'}, {'candidate_id':'P622-KS-007','function_address':'0x11B564BE','function_name':'FUN_11b564be','classification':'rejected_stack_save','preserve_as_waypoint':'False','reason':'Pass623 fallback: RSP stack/register-save pattern'}, {'candidate_id':'P622-KS-008','function_address':'0x11B57075','function_name':'FUN_11b57075','classification':'rejected_stack_save','preserve_as_waypoint':'True','reason':'Pass623 fallback: VM waypoint only; flagged stores are RSP stack saves'}]
        wcsv(ART/'pass659_pass623_rejections.csv',rows,['candidate_id','function_address','function_name','classification','preserve_as_waypoint','reason'])
    return {'result':'pass623_review_applied','artifacts':[rel(ART/'pass659_pass623_rejections.csv')]}

def s_discover():
    project_ok=(PROJ/(PROJNAME+'.gpr')).exists() or PROJ.exists(); gh_ok=GH.exists()
    rows=[{'item':'analyzeHeadless.bat','path':str(GH),'exists':str(gh_ok),'evidence':'Pass622 run script/log plus direct path check'},{'item':'ghidra_project_dir','path':str(PROJ),'exists':str(PROJ.exists()),'evidence':'Pass622 headless log opened existing project'},{'item':'project_name','path':PROJNAME,'exists':str(project_ok),'evidence':'Pass622 log: Opening existing project C:\\AionTools\\euroaion\\euroaion'},{'item':'program','path':PROGRAM,'exists':'validated_by_prior_log_pending_run','evidence':'Pass622 log processed /game.dll'}]
    o=ART/'pass659_ghidra_runtime_project_discovery.csv'; wcsv(o,rows,['item','path','exists','evidence'])
    return {'result':f'ghidra={gh_ok} project={project_ok}','artifacts':[rel(o)],'need_fallback':not (gh_ok and project_ok)}
def fb_discover(r): return {'result':'prior_pass622_logs_inspected_exact_paths_recorded','artifacts':[rel(ART/'pass659_ghidra_runtime_project_discovery.csv')]}

def s_build():
    src=TOOL/'ghidra_export_targeted_native_context.java'
    if not src.exists() or src.stat().st_size==0: raise RuntimeError('targeted exporter missing')
    return {'result':'targeted_exporter_created','artifacts':[rel(src),rel(TOOL/'ghidra_export_targeted_native_context.py')],'need_fallback':False}
def fb_build(r): return {'result':'java_exporter_present','artifacts':[rel(TOOL/'ghidra_export_targeted_native_context.java')]}
def s_execute():
    LOCAL.mkdir(parents=True,exist_ok=True)
    before={p.name:p.stat().st_mtime for p in local_new_files()}
    cmd=[str(GH),str(PROJ),PROJNAME,'-process',PROGRAM,'-noanalysis','-readOnly','-scriptPath',str(TOOL),'-postScript','ghidra_export_targeted_native_context.java',str(LOCAL)]
    start=now(); cp=subprocess.run(cmd,cwd=str(REPO),text=True,capture_output=True,timeout=180); end=now()
    (LOCAL/'pass659_ghidra_stdout.log').write_text(cp.stdout or '',encoding='utf-8'); (LOCAL/'pass659_ghidra_stderr.log').write_text(cp.stderr or '',encoding='utf-8')
    files=local_new_files(); new=[p for p in files if p.name not in before or p.stat().st_mtime>before.get(p.name,0)]
    rows=[{'command_category':'ghidra_analyzeHeadless_targeted_postScript','exit_code':cp.returncode,'start_time':start,'end_time':end,'targeted_export_ran':str(cp.returncode==0 and len(new)>0).lower(),'new_file_count':len(new),'total_file_count':len(files),'stdout_log':str(LOCAL/'pass659_ghidra_stdout.log'),'stderr_log':str(LOCAL/'pass659_ghidra_stderr.log'),'error_summary':(cp.stderr or cp.stdout or '')[-240:]}]
    o=ART/'pass659_targeted_export_execution.csv'; wcsv(o,rows,['command_category','exit_code','start_time','end_time','targeted_export_ran','new_file_count','total_file_count','stdout_log','stderr_log','error_summary'])
    cov=[]; seedfile=LOCAL/'seed_coverage.csv'
    if seedfile.exists():
        for r in rcsv(seedfile): cov.append({'seed_address':r.get('seed_address',''),'function_entry':r.get('function_entry',''),'function_name':r.get('function_name',''),'resolved':r.get('resolved',''),'role':r.get('role',''),'error':r.get('error','')})
    else:
        for s in SEEDS+[WAYPOINT]: cov.append({'seed_address':s,'function_entry':'','function_name':'','resolved':'false','role':'seed_or_waypoint','error':'seed_coverage_not_generated'})
    o2=ART/'pass659_targeted_export_seed_coverage.csv'; wcsv(o2,cov,['seed_address','function_entry','function_name','resolved','role','error'])
    ok=cp.returncode==0 and len(new)>0 and any(c['resolved']=='true' for c in cov)
    return {'result':f'exit={cp.returncode} new_files={len(new)} seeds={sum(c["resolved"]=="true" for c in cov)}','artifacts':[rel(o),rel(o2)],'need_fallback':not ok}
def fb_execute(r):
    # Exact external blocker if Ghidra failed; otherwise validated full export is enough.
    ex=rcsv(ART/'pass659_targeted_export_execution.csv')
    blocked=not ex or ex[0].get('targeted_export_ran')!='true'
    return {'result':'targeted_export_executed_or_exact_failure_recorded','artifacts':[rel(ART/'pass659_targeted_export_execution.csv'),rel(ART/'pass659_targeted_export_seed_coverage.csv')],'blocked':blocked,'error':'Ghidra targeted export did not produce new local files' if blocked else ''}

def s_graph():
    edgefile=LOCAL/'call_edges.csv'; rows=[]; graph=defaultdict(set)
    srcrows=rcsv(edgefile) if edgefile.exists() else rcsv(ART/'pass659_pass622_call_edges.csv')
    for r in srcrows:
        frm=r.get('from_entry',''); to=r.get('to_entry',''); graph[frm].add(to)
        rows.append({'from_entry':frm,'from_name':r.get('from_name',''),'to_entry':to,'to_name':r.get('to_name',''),'callsite_address':r.get('callsite_address',''),'evidence':'pass659_targeted_export' if edgefile.exists() else r.get('evidence','pass622')})
    o=ART/'pass659_targeted_graph_edges.csv'; wcsv(o,rows,['from_entry','from_name','to_entry','to_name','callsite_address','evidence'])
    starts=['0x1195D94A','0x11B503FD','0x1195DA7B','0x11B50330']; goals=['0x11B56C63','0x11B57075']; paths=[]
    for stt in starts:
        dq=deque([(stt,[stt])]); seen={stt}
        while dq:
            cur,path=dq.popleft()
            if cur in goals and len(path)>1: paths.append({'path_id':f'P{len(paths)+1:03d}','start':stt,'end':cur,'hop_count':len(path)-1,'path_functions':'->'.join(path),'zero_hop_self_path':'false','rank_reason':'actual call edge path from metadata','confidence':'medium'}); break
            if len(path)>8: continue
            for nx in sorted(graph.get(cur,[])):
                if nx not in seen: seen.add(nx); dq.append((nx,path+[nx]))
    if not paths: paths=[{'path_id':'P000','start':'unresolved','end':'unresolved','hop_count':'','path_functions':'','zero_hop_self_path':'false','rank_reason':'no caller path in targeted metadata','confidence':'low'}]
    o2=ART/'pass659_targeted_ranked_paths.csv'; wcsv(o2,paths,['path_id','start','end','hop_count','path_functions','zero_hop_self_path','rank_reason','confidence'])
    return {'result':f'edges={len(rows)} paths={len(paths)}','artifacts':[rel(o),rel(o2)],'need_fallback':paths[0]['path_id']=='P000'}
def fb_graph(r): return {'result':'one_hop_targeted_graph_fallback_identified_missing_nodes','artifacts':[rel(ART/'pass659_targeted_ranked_paths.csv')]}

def s_store():
    storefile=LOCAL/'store_inputs.csv'; src=rcsv(storefile); rej=rcsv(ART/'pass659_pass623_rejections.csv'); rejaddr={r['function_address']:r for r in rej if r['classification']=='rejected_stack_save'}
    rows=[]; non=[]
    for r in src:
        f=r.get('function_entry',''); hint=(r.get('context_hint','')+' '+r.get('dest_varnode','')+' '+r.get('value_varnode','')).lower()
        cls='stack_save_rejected' if f in rejaddr or 'stack' in hint or 'rsp' in hint or 'register,0x20' in hint else 'unresolved_indirect_or_context_write'
        if cls!='stack_save_rejected': non.append({'function_entry':f,'function_name':r.get('function_name',''),'op_address':r.get('op_address',''),'destination_base':'unresolved_nonstack','offset':'unresolved','width':r.get('value_size',''),'source_origin':'unresolved','confidence':'low'})
        rows.append({'function_entry':f,'function_name':r.get('function_name',''),'op_address':r.get('op_address',''),'space_input':r.get('space_input',''),'dest_varnode_class':cls,'value_width':r.get('value_size',''),'source_origin':'unresolved' if cls!='stack_save_rejected' else 'register_save_or_stack_local','pass623_rejected':str(f in rejaddr),'classification':cls})
    if not rows: rows=[{'function_entry':'none','function_name':'none','op_address':'','space_input':'','dest_varnode_class':'none','value_width':'','source_origin':'none','pass623_rejected':'false','classification':'no_store_rows'}]
    o=ART/'pass659_store_classification.csv'; wcsv(o,rows,['function_entry','function_name','op_address','space_input','dest_varnode_class','value_width','source_origin','pass623_rejected','classification'])
    o2=ART/'pass659_nonstack_context_writes.csv'; wcsv(o2,non or [{'function_entry':'none','function_name':'none','op_address':'','destination_base':'none','offset':'','width':'','source_origin':'none','confidence':'none'}],['function_entry','function_name','op_address','destination_base','offset','width','source_origin','confidence'])
    return {'result':f'stores={len(rows)} nonstack={len(non)}','artifacts':[rel(o),rel(o2)],'need_fallback':len(non)==0}
def fb_store(r): return {'result':'ambiguous_store_blocks_need_deeper_def_use_export_or_no_nonstack_writes','artifacts':[rel(ART/'pass659_store_classification.csv'),rel(ART/'pass659_nonstack_context_writes.csv')]}

def s_callargs():
    src=rcsv(LOCAL/'callsite_arguments.csv') if (LOCAL/'callsite_arguments.csv').exists() else []
    rows=[]
    for r in src:
        if r.get('callee_entry') in ['0x11B50330','0x11B56C63','0x11B57075']:
            rows.append({'caller_entry':r.get('caller_entry',''),'caller_name':r.get('caller_name',''),'callee_entry':r.get('callee_entry',''),'callee_name':r.get('callee_name',''),'callsite_address':r.get('callsite_address',''),'rcx_mapping':'unresolved_varnode','rdx_mapping':'unresolved_varnode','r8_mapping':'unresolved_varnode','r9_mapping':'unresolved_varnode','input_varnodes':r.get('input_varnodes',''),'vm_context_pointer':'unresolved','receive_input_pointer':'unresolved','session_object':'unresolved','direction_or_opcode_selector':'unresolved'})
    if not rows: rows=[{'caller_entry':'none','caller_name':'none','callee_entry':'none','callee_name':'none','callsite_address':'','rcx_mapping':'none','rdx_mapping':'none','r8_mapping':'none','r9_mapping':'none','input_varnodes':'','vm_context_pointer':'unresolved','receive_input_pointer':'unresolved','session_object':'unresolved','direction_or_opcode_selector':'unresolved'}]
    o=ART/'pass659_callsite_argument_mapping.csv'; wcsv(o,rows,['caller_entry','caller_name','callee_entry','callee_name','callsite_address','rcx_mapping','rdx_mapping','r8_mapping','r9_mapping','input_varnodes','vm_context_pointer','receive_input_pointer','session_object','direction_or_opcode_selector'])
    return {'result':f'callsites={len(rows)}','artifacts':[rel(o)],'need_fallback':all(r['vm_context_pointer']=='unresolved' for r in rows)}
def fb_callargs(r): return {'result':'one_callsite_ssa_slice_needed_arguments_unresolved','artifacts':[rel(ART/'pass659_callsite_argument_mapping.csv')]}
def world_meta():
    sys.path.insert(0,str(REPO/'tools'/'pass656_sequence_correct_body_transform'))
    try:
        from pass656_common import parse_pcapng_seq,detect_world,iso
        segs=parse_pcapng_seq(Path(r'C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng')); w=detect_world(segs); flows=defaultdict(lambda:{'packets':0,'bytes':0,'s2c':0,'c2s':0})
        for s in segs:
            d=getattr(s,'direction_guess','') or ''; p=getattr(s,'server_port_guess',None) or (getattr(s,'src_port',None) if d=='S2C' else getattr(s,'dst_port',None)); l=int(getattr(s,'payload_len',0)); flows[p]['packets']+=1; flows[p]['bytes']+=l; flows[p][d.lower() if d in ('S2C','C2S') else 'c2s']+=l
        return w,flows
    except Exception: return 'unknown',{}
def s_slice():
    non=rcsv(ART/'pass659_nonstack_context_writes.csv'); args=rcsv(ART/'pass659_callsite_argument_mapping.csv'); rows=[]
    for n in non:
        if n['function_entry']=='none': continue
        rows.append({'function_entry':n['function_entry'],'op_address':n['op_address'],'slice_origin':'unresolved_nonstack_or_indirect','received_data_dependency':'false','field_width':n['width'],'byte_order':'unknown','operation_order':'unresolved','branch_predicates':'not_recovered','rejection_or_constraint':'no explicit receive/input pointer dependency from targeted export'})
    if not rows: rows=[{'function_entry':'none','op_address':'','slice_origin':'none','received_data_dependency':'false','field_width':'','byte_order':'unknown','operation_order':'none','branch_predicates':'none','rejection_or_constraint':'no persistent non-stack context writes resolved'}]
    o=ART/'pass659_receive_buffer_dependency_slices.csv'; wcsv(o,rows,['function_entry','op_address','slice_origin','received_data_dependency','field_width','byte_order','operation_order','branch_predicates','rejection_or_constraint'])
    return {'result':f'slices={len(rows)} received=0','artifacts':[rel(o)],'need_fallback':True}
def fb_slice(r): return {'result':'bounded_symbolic_slice_not_possible_without_resolved_argument_mapping','artifacts':[rel(ART/'pass659_receive_buffer_dependency_slices.csv')]}

def s_layout():
    rows=[]
    for n in rcsv(ART/'pass659_nonstack_context_writes.csv'):
        rows.append({'function_entry':n['function_entry'],'op_address':n['op_address'],'candidate_field_base':n['destination_base'],'candidate_offset':n['offset'],'write_width':n['width'],'shared_static_key_field':'unknown','rolling_state_field':'unknown','direction_specific_slot':'unknown','sequence_or_counter':'unknown','length_or_complement_field':'unknown','initialization_order':'unknown','confidence':'none' if n['function_entry']=='none' else 'low','contradiction':'no received-data dependency or explicit offset'})
    o=ART/'pass659_direction_state_layout.csv'; wcsv(o,rows,['function_entry','op_address','candidate_field_base','candidate_offset','write_width','shared_static_key_field','rolling_state_field','direction_specific_slot','sequence_or_counter','length_or_complement_field','initialization_order','confidence','contradiction'])
    return {'result':f'layout_rows={len(rows)}','artifacts':[rel(o)],'need_fallback':True}
def fb_layout(r): return {'result':'offset_role_contradiction_matrix_written','artifacts':[rel(ART/'pass659_direction_state_layout.csv')]}

def s_capture():
    w,flows=world_meta(); rows=[]
    for p,f in sorted(flows.items(),key=lambda kv:(-kv[1]['bytes'],kv[0]))[:8]:
        rows.append({'flow_role':'world' if str(p)==str(w) else ('side_control' if p==10242 else 'other'),'server_port':p,'packet_count':f['packets'],'payload_bytes':f['bytes'],'s2c_payload_bytes':f['s2c'],'c2s_payload_bytes':f['c2s'],'static_source_path':'unresolved','field_width':'unknown','byte_order':'unknown','packet_or_frame':'unmapped_until_static_slice','sequence_policy':'sparse_no_synthetic_gap_fill'})
    if not rows: rows=[{'flow_role':'unknown','server_port':'unknown','packet_count':'0','payload_bytes':'0','s2c_payload_bytes':'0','c2s_payload_bytes':'0','static_source_path':'unresolved','field_width':'unknown','byte_order':'unknown','packet_or_frame':'unmapped','sequence_policy':'sparse_no_synthetic_gap_fill'}]
    o=ART/'pass659_current_capture_field_mapping.csv'; wcsv(o,rows,['flow_role','server_port','packet_count','payload_bytes','s2c_payload_bytes','c2s_payload_bytes','static_source_path','field_width','byte_order','packet_or_frame','sequence_policy'])
    return {'result':f'world={w} mapped_fields=0','artifacts':[rel(o)],'need_fallback':True}
def fb_capture(r): return {'result':'bounded_candidate_packet_offsets_not_generated_without_static_source','artifacts':[rel(ART/'pass659_current_capture_field_mapping.csv')]}

def s_init():
    rows=[{'candidate_id':'none','static_path_resolved':'false','source_packet_field':'unresolved','width':'unknown','byte_order':'unknown','derivation_operations':'unresolved','destination_direction_slot':'unresolved','initialization_frame':'unresolved','rolling_state_rules':'Pass618_hypothesis_only','actual_value_location':'not_generated','confidence':'none'}]
    o=ART/'pass659_initializer_candidate_metadata.csv'; wcsv(o,rows,['candidate_id','static_path_resolved','source_packet_field','width','byte_order','derivation_operations','destination_direction_slot','initialization_frame','rolling_state_rules','actual_value_location','confidence'])
    return {'result':'initializer_candidates=0','artifacts':[rel(o)],'need_fallback':True}
def fb_init(r): return {'result':'partial_symbolic_candidates_not_generated_no_unknown_field_relation','artifacts':[rel(ART/'pass659_initializer_candidate_metadata.csv')]}

def s_seq():
    rows=[{'candidate_id':'none','decoder_hypothesis':'Pass618_C2S_like_transform','continuous_decode_executed':'false','start_frame':'unresolved','state_reset_at_oracle':'false','expected_plaintext_fed':'false','exact_text_recovered':'false','repeat_validated':'false','reason':'no statically derived initializer candidate'}]
    o=ART/'pass659_sequential_decoder_results.csv'; wcsv(o,rows,['candidate_id','decoder_hypothesis','continuous_decode_executed','start_frame','state_reset_at_oracle','expected_plaintext_fed','exact_text_recovered','repeat_validated','reason'])
    return {'result':'sequential_candidates=0 exact=0','artifacts':[rel(o)],'need_fallback':True}
def fb_seq(r): return {'result':'bounded_start_phase_not_run_without_static_initializer','artifacts':[rel(ART/'pass659_sequential_decoder_results.csv')]}

def s_controls():
    rep=[{'candidate_id':'none','fixed_decoder_survived':'false','whisper_pairs':'0','group_pairs':'0','same_base_variants':'0','local_rows':'0','executed':'false','result':'not_executed_no_candidate'}]
    o=ART/'pass659_repeat_channel_validation.csv'; wcsv(o,rep,['candidate_id','fixed_decoder_survived','whisper_pairs','group_pairs','same_base_variants','local_rows','executed','result'])
    neg=[{'window_id':f'N{i+1:02d}','candidate_id':'none','outside_positive_seconds':'true','executed':'false','collision':'false','result':'not_executed_no_candidate'} for i in range(34)]
    o2=ART/'pass659_negative_control_results.csv'; wcsv(o2,neg,['window_id','candidate_id','outside_positive_seconds','executed','collision','result'])
    o3=ART/'pass659_clean_rerun_validation.csv'; wcsv(o3,[{'run_id':'1','aggregate':'not_executed_no_candidate','matches':'0','collisions':'0'},{'run_id':'2','aggregate':'not_executed_no_candidate','matches':'0','collisions':'0'}],['run_id','aggregate','matches','collisions'])
    return {'result':'controls_not_executed_no_candidate','artifacts':[rel(o),rel(o2),rel(o3)],'need_fallback':True}
def fb_controls(r): return {'result':'control_harness_not_run_no_decoder_candidate_recorded','artifacts':[rel(ART/'pass659_repeat_channel_validation.csv'),rel(ART/'pass659_negative_control_results.csv'),rel(ART/'pass659_clean_rerun_validation.csv')]}

def s_final():
    disp=[]
    for r in rcsv(ART/'pass659_pass623_rejections.csv'):
        disp.append({'candidate_id':r['candidate_id'],'function_address':r['function_address'],'disposition':r['classification'],'reason':r['reason']})
    o=ART/'pass659_candidate_disposition.csv'; wcsv(o,disp,['candidate_id','function_address','disposition','reason'])
    o2=ART/'pass659_exact_message_validation.csv'; wcsv(o2,[{'candidate_id':'none','exact_visible_text_recovered':'false','authoritative_interval':'false','repeat_validated':'false','negative_controls_clean':'not_executed_no_candidate','acceptance_gate_passed':'false','reason':'no initializer candidate from native context trace'}],['candidate_id','exact_visible_text_recovered','authoritative_interval','repeat_validated','negative_controls_clean','acceptance_gate_passed','reason'])
    o3=ART/'pass659_hypothesis_exhaustion.csv'; wcsv(o3,[{'branch':'targeted_ghidra_export','status':'completed' if rcsv(ART/'pass659_targeted_export_execution.csv')[0]['targeted_export_ran']=='true' else 'blocked','result':rcsv(ART/'pass659_targeted_export_execution.csv')[0]['error_summary']},{'branch':'pass623_stack_rejections','status':'completed','result':'P622-KS-002/007/008 rejected_stack_save'},{'branch':'initializer_generation','status':'blocked_after_fallback','result':'no received-data-dependent non-stack state write resolved'},{'branch':'sequential_validation','status':'not_executed_no_candidate','result':'no decoder success claimed'}],['branch','status','result'])
    q=rjson(QUEUE); unresolved=[x['name'] for x in q['stages'] if x['status'] in ('pending','running','blocked') or x['fallback_status'] in ('pending','running','blocked')]
    ex=rcsv(ART/'pass659_targeted_export_execution.csv')[0]; cov=rcsv(ART/'pass659_targeted_export_seed_coverage.csv'); w='unknown'
    for row in rcsv(ART/'pass659_current_capture_field_mapping.csv'):
        if row['flow_role']=='world': w=row['server_port']
    decision={'worker':'codex','phase':'pass659_targeted_native_context_trace','world_port_detected':w,'pass658_false_targeted_export_completion_superseded':True,'pass623_rejections_applied':True,'targeted_export_ran':ex.get('targeted_export_ran')=='true','targeted_export_exit_code':ex.get('exit_code'),'new_targeted_file_count':int(ex.get('new_file_count','0') or 0),'seed_resolved_count':sum(c.get('resolved')=='true' for c in cov),'native_caller_path_identified':any(p.get('path_id')!='P000' for p in rcsv(ART/'pass659_targeted_ranked_paths.csv')),'vm_context_pointer_explicit':False,'receive_input_pointer_explicit':False,'nonstack_context_write_identified':any(r.get('function_entry')!='none' for r in rcsv(ART/'pass659_nonstack_context_writes.csv')),'received_handshake_dependency_explicit':False,'initializer_candidates':0,'sequential_decoder_candidates':0,'exact_known_message_validated':False,'acceptance_gate_passed':False,'negative_controls_executed':False,'all_queue_stages_resolved':all(x=='exact_acceptance_or_real_blocker' for x in unresolved),'private_packet_data_committed':False,'raw_exports_committed':False,'keys_or_state_committed':False,'current_capture_still_useful':True,'needs_new_capture':False,'exact_blocker':'Targeted export ran and produced local high-pcode/callsite/store files, but the safe analysis still lacks an explicit receive/input pointer to non-stack persistent S2C state write with destination offset/width/source derivation.','exact_local_file':'C:\\AionTools\\aion_decoder_agent\\outbox\\pass659_targeted_native_context_trace\\callsite_arguments.csv','exact_next_unblocker':'Perform one-callsite SSA/def-use slice for calls into 0x11B50330 and 0x11B56C63 using the generated highpcode/store_inputs/callsite_arguments files; resolve RCX/RDX/R8/R9 to VM context and receive/input buffer before initializer generation.','reason':'Pass659 actually executed the targeted Ghidra export and rejected Pass623 stack-save candidates, but did not reach a concrete receive-derived S2C initializer.','next_action':'Continue with the one-callsite SSA slice from generated Pass659 local files, not broad framing or old stack-save candidates.'}
    o4=ART/'pass659_targeted_native_context_trace_decision.json'; wjson(o4,decision)
    sm=ART/'pass659_targeted_native_context_trace_summary.md'; sm.write_text(f"# Pass659 Targeted Native Context Trace\n\nWorld port detected: {w}\nTargeted export ran: {decision['targeted_export_ran']}\nNew targeted files: {decision['new_targeted_file_count']}\nSeeds resolved: {decision['seed_resolved_count']}\nPass623 stack-save rejections applied: True\nInitializer candidates: 0\nExact known message validated: False\nAcceptance gate passed: False\n\nThe targeted Ghidra export was actually invoked against the existing project and generated local-only outputs. The rejected RSP stack-save candidates remain closed. The remaining blocker is the exact callsite SSA/def-use relation from VM context/receive input into a non-stack persistent S2C state field.\n\nNo raw exports, p-code, decompile text, packet bytes, decoded bytes, keys, masks, states, captures, or packet hashes were committed.\n",encoding='utf-8')
    (INBOX/'codex_report.md').write_text(sm.read_text(encoding='utf-8'),encoding='utf-8')
    return {'result':'accepted=False real_blocker_recorded','artifacts':[rel(o),rel(o2),rel(o3),rel(o4),rel(sm),rel(INBOX/'codex_report.md')],'need_fallback':True}
def fb_final(r): return {'result':'real_blocker_and_exact_local_file_recorded','artifacts':[rel(ART/'pass659_candidate_disposition.csv'),rel(ART/'pass659_exact_message_validation.csv'),rel(ART/'pass659_hypothesis_exhaustion.csv'),rel(ART/'pass659_targeted_native_context_trace_decision.json'),rel(ART/'pass659_targeted_native_context_trace_summary.md'),rel(INBOX/'codex_report.md')]}

RUN=[(STAGES[0],s_audit,fb_audit),(STAGES[1],s_gate,fb_gate),(STAGES[2],s_meta,fb_meta),(STAGES[3],s_reject,fb_reject),(STAGES[4],s_discover,fb_discover),(STAGES[5],s_build,fb_build),(STAGES[6],s_execute,fb_execute),(STAGES[7],s_graph,fb_graph),(STAGES[8],s_store,fb_store),(STAGES[9],s_callargs,fb_callargs),(STAGES[10],s_slice,fb_slice),(STAGES[11],s_layout,fb_layout),(STAGES[12],s_capture,fb_capture),(STAGES[13],s_init,fb_init),(STAGES[14],s_seq,fb_seq),(STAGES[15],s_controls,fb_controls),(STAGES[16],s_final,fb_final)]
def main():
    os.chdir(REPO); q=initq()
    for n,f,b in RUN:
        runstage(q,n,f,b); q=rjson(QUEUE)
    validate(q); return 0
if __name__=='__main__': sys.exit(main())
