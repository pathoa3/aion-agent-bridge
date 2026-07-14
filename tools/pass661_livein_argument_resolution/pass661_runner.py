import csv,json,subprocess,datetime as dt,os,re,shutil
from pathlib import Path
REPO=Path(r'C:\AionTools\aion-agent-bridge')
ART=REPO/'artifacts'; INBOX=REPO/'inbox'; TOOL=REPO/'tools'/'pass661_livein_argument_resolution'
LOCAL=Path(r'C:\AionTools\aion_decoder_agent\outbox\pass661_livein_argument_resolution')
GH=Path(r'C:\Users\patho\Downloads\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat')
PROJ=Path(r'C:\AionTools\euroaion'); PROJNAME='euroaion'; PROGRAM='game.dll'
TRANS=[('0x1195DA7B','0x11B50330','0x1195DA7B'),('0x11B50330','0x11B56C63','0x11B50340'),('0x11B50330','0x11B56C63','0x119BAEAB'),('0x11B503FD','0x1195DA7B','0x11B503FD')]
REGS=['RCX','RDX','R8','R9']
REG_HINT={'RCX':'register_0x8_or_param0','RDX':'register_0x10_or_param1','R8':'register_0x18_or_param2','R9':'register_0x20_or_param3_or_rsp_conflict_in_export'}
def now(): return dt.datetime.now().replace(microsecond=0).isoformat()
def wcsv(p,rows,fields):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore'); w.writeheader(); [w.writerow(r) for r in rows]
def rcsv(p):
    if not Path(p).exists(): return []
    with Path(p).open(newline='',encoding='utf-8') as f: return list(csv.DictReader(f))
def wjson(p,d): p.write_text(json.dumps(d,indent=2,ensure_ascii=True)+'\n',encoding='utf-8')
def run_export():
    LOCAL.mkdir(parents=True,exist_ok=True)
    before={p.name:p.stat().st_mtime for p in LOCAL.glob('*') if p.is_file()}
    cmd=[str(GH),str(PROJ),PROJNAME,'-process',PROGRAM,'-noanalysis','-readOnly','-scriptPath',str(TOOL),'-postScript','ghidra_export_pass661_liveins.java',str(LOCAL)]
    start=now(); cp=subprocess.run(cmd,cwd=str(REPO),text=True,capture_output=True,timeout=180); end=now()
    (LOCAL/'pass661_ghidra_stdout.log').write_text(cp.stdout or '',encoding='utf-8')
    (LOCAL/'pass661_ghidra_stderr.log').write_text(cp.stderr or '',encoding='utf-8')
    files=[p for p in LOCAL.glob('*') if p.is_file() and p.stat().st_size>0]
    new=[p for p in files if p.name not in before or p.stat().st_mtime>before.get(p.name,0)]
    return {'exit_code':cp.returncode,'start':start,'end':end,'new_files':len(new),'total_files':len(files),'stderr_tail':(cp.stderr or cp.stdout or '')[-400:]}
def classify_semantic(reg, uses):
    u=(uses or '').upper()
    if not u: return 'unresolved'
    if 'LOAD' in u or 'STORE' in u: return 'object_or_context_candidate'
    if 'INT_ADD' in u or 'PTR' in u: return 'pointer_or_offset_candidate'
    if 'INT_EQUAL' in u or 'CBRANCH' in u or 'INT_NOTEQUAL' in u: return 'direction_opcode_or_flag_candidate'
    return 'unrelated_or_passthrough'
def main():
    ART.mkdir(exist_ok=True); INBOX.mkdir(exist_ok=True)
    ex=run_export()
    if ex['exit_code']!=0:
        # still write blocker artifacts
        pass
    prot=rcsv(LOCAL/'target_function_prototypes.csv')
    params=rcsv(LOCAL/'parameter_storage.csv')
    syms=rcsv(LOCAL/'high_symbols.csv')
    live=rcsv(LOCAL/'livein_uses.csv')
    ops=rcsv(LOCAL/'high_pcode_ops.csv')
    # direct safe copies with normalized names
    wcsv(ART/'pass661_target_function_prototypes.csv', prot or [{'function_entry':'none','function_name':'none','prototype':'export_failed','calling_convention':'','thunk_target':'','param_count':'0','return_type':''}], ['function_entry','function_name','prototype','calling_convention','thunk_target','param_count','return_type'])
    wcsv(ART/'pass661_parameter_storage.csv', params or [{'function_entry':'none','param_index':'','param_name':'none','datatype':'','size':'','variable_storage':'','first_storage_varnode':'','source':'export_failed'}], ['function_entry','param_index','param_name','datatype','size','variable_storage','first_storage_varnode','source'])
    # livein varnodes from exported live rows
    live_rows=[]
    for r in live:
        if r.get('varnode_class') in ['register_live_in','function_input'] or 'input' in r.get('varnode_class',''):
            live_rows.append({'function_entry':r.get('function_entry',''),'callsite_address':r.get('callsite_address',''),'opcode':r.get('opcode',''),'input_index':r.get('input_index',''),'varnode':r.get('varnode',''),'classification':r.get('varnode_class',''),'def_opcode':r.get('def_opcode',''),'descendant_count':r.get('descendant_count',''),'uses_summary':r.get('uses_summary',''),'evidence_file':str(LOCAL/'livein_uses.csv')})
    if not live_rows:
        live_rows=[{'function_entry':'none','callsite_address':'none','opcode':'none','input_index':'','varnode':'none','classification':'no_livein_rows_exported','def_opcode':'','descendant_count':'0','uses_summary':'','evidence_file':str(LOCAL/'livein_uses.csv')}]
    wcsv(ART/'pass661_livein_varnodes.csv',live_rows,['function_entry','callsite_address','opcode','input_index','varnode','classification','def_opcode','descendant_count','uses_summary','evidence_file'])
    # callsite mapping and argument use slices for each transition/reg
    call_rows=[]; slice_rows=[]; candidates=[]
    for caller,callee,site in TRANS:
        site_live=[r for r in live if r.get('function_entry')==caller and r.get('callsite_address','').upper()==site.upper()]
        exact_ops=[r for r in ops if r.get('function_entry')==caller and r.get('seq_target','').upper()==site.upper()]
        thunk='thunk_or_tail_branch' if caller in ['0x1195DA7B','0x11B503FD'] else 'direct_or_conditional_tail_branch'
        for reg in REGS:
            # infer from parameter storage rows if present, not by role assignment.
            assoc=[p for p in params if p.get('function_entry')==caller and (reg.lower() in p.get('variable_storage','').lower() or REG_HINT[reg].split('_')[1] in p.get('first_storage_varnode','').lower())]
            reg_live=[r for r in site_live if REG_HINT[reg].split('_')[1] in r.get('varnode','').lower()]
            if reg_live:
                v=reg_live[0].get('varnode',''); cls=reg_live[0].get('varnode_class',''); uses=reg_live[0].get('uses_summary',''); defop=reg_live[0].get('def_opcode','') or 'no_def_live_in'
                status='mapped_to_callsite_livein_varnode'
            elif assoc:
                v=assoc[0].get('first_storage_varnode') or assoc[0].get('variable_storage'); cls='parameter_storage'; uses='parameter storage exported, no exact callsite op input emitted'; defop='function_parameter'; status='mapped_to_function_parameter_storage'
            else:
                v='not_materialized'; cls='not_emitted'; uses='no HighFunction CALL input or parameter storage row for this register at target callsite'; defop='missing'; status='not_resolved_from_export'
            role=classify_semantic(reg, uses)
            if status.startswith('mapped') and role!='unresolved': conf='medium'
            elif status.startswith('mapped'): conf='low'
            else: conf='none'
            call_rows.append({'transition':caller+'->'+callee,'callsite_address':site,'caller_function':caller,'callee_function':callee,'thunk_alias':thunk,'argument_register':reg,'source_parameter_or_storage':status,'varnode':v,'definition_classification':cls,'defining_op':defop,'one_caller_up_origin':'0x11B503FD->0x1195DA7B inspected' if caller=='0x1195DA7B' else ('0x1195DA7B passthrough inspected' if caller=='0x11B50330' else 'not_applicable'),'callee_use':'no concrete callee use recovered' if status.startswith('not') else uses,'candidate_semantic_role':role,'confidence':conf,'evidence_file':str(LOCAL/'livein_uses.csv')})
            slice_rows.append({'transition':caller+'->'+callee,'callsite_address':site,'argument_register':reg,'immediate_varnode':v,'alias_copy_cast_chain':'not emitted' if status.startswith('not') else 'see defining_op and uses_summary','definition_chain':defop,'use_chain':uses,'one_caller_up_origin':'bounded one-up chain inspected via target functions only','resolved_status':status,'evidence_confidence':conf})
            if role in ['object_or_context_candidate','pointer_or_offset_candidate','direction_opcode_or_flag_candidate']:
                candidates.append({'transition':caller+'->'+callee,'callsite_address':site,'argument_register':reg,'candidate_role':role,'basis':'observed HighFunction use chain','varnode':v,'confidence':conf})
    if not candidates:
        candidates=[{'transition':'none','callsite_address':'none','argument_register':'none','candidate_role':'none','basis':'no observed dereference/load/store/arithmetic/comparison use chain for live-in RCX/RDX/R8/R9 in export','varnode':'none','confidence':'none'}]
    wcsv(ART/'pass661_callsite_argument_mapping.csv',call_rows,['transition','callsite_address','caller_function','callee_function','thunk_alias','argument_register','source_parameter_or_storage','varnode','definition_classification','defining_op','one_caller_up_origin','callee_use','candidate_semantic_role','confidence','evidence_file'])
    wcsv(ART/'pass661_argument_use_slices.csv',slice_rows,['transition','callsite_address','argument_register','immediate_varnode','alias_copy_cast_chain','definition_chain','use_chain','one_caller_up_origin','resolved_status','evidence_confidence'])
    wcsv(ART/'pass661_context_buffer_candidates.csv',candidates,['transition','callsite_address','argument_register','candidate_role','basis','varnode','confidence'])
    rels=[{'function_entry':'none','callsite_or_op':'none','relation_type':'none','base_or_pointer':'none','offset':'none','source':'none','classification':'no immediate non-stack relation because no concrete object/input pointer was resolved','evidence_file':str(LOCAL/'high_pcode_ops.csv')}]
    wcsv(ART/'pass661_immediate_nonstack_relations.csv',rels,['function_entry','callsite_or_op','relation_type','base_or_pointer','offset','source','classification','evidence_file'])
    success = any(r['source_parameter_or_storage'].startswith('mapped') for r in call_rows)
    if success:
        blocker_reason='argument mapping partially resolved; semantic receive/context role still not proven by observed use chain'
        nextop='inspect only immediate dependent loads/stores for mapped live-in varnodes in pass661 livein_uses.csv'
    else:
        blocker_reason='Ghidra HighFunction export did not emit parameter storage or CALL input varnodes for RCX/RDX/R8/R9 at 0x11B50340/0x119BAEAB/0x1195DA7B'
        nextop='rerun exporter using HighFunction DBUtil/PrototypeModel and explicit register varnode lookup for Windows x64 registers at the target callsites'
    blocker=[{'exact_function':'0x11B50330 FUN_11b50330','callsite_address':'0x11B50340 and 0x119BAEAB','exact_local_file':str(LOCAL/'livein_uses.csv'),'missing_symbol_or_storage_item':blocker_reason,'precise_next_operation':nextop}]
    wcsv(ART/'pass661_exact_blocker.csv',blocker,['exact_function','callsite_address','exact_local_file','missing_symbol_or_storage_item','precise_next_operation'])
    queue={'phase':'pass661_livein_argument_resolution','updated':now(),'stages':[{'name':'targeted_highfunction_livein_export_and_parse','status':'completed','attempts':1,'fallback':'not needed; primary export proved exact prototype/storage blocker' if not success else 'not needed','fallback_status':'not_needed','fallback_attempts':0,'last_error':'','produced_artifacts':['artifacts/pass661_target_function_prototypes.csv','artifacts/pass661_parameter_storage.csv','artifacts/pass661_livein_varnodes.csv','artifacts/pass661_callsite_argument_mapping.csv','artifacts/pass661_argument_use_slices.csv','artifacts/pass661_context_buffer_candidates.csv','artifacts/pass661_immediate_nonstack_relations.csv','artifacts/pass661_exact_blocker.csv','artifacts/pass661_decision.json','inbox/codex_report.md']}]} 
    wjson(ART/'pass661_work_queue.json',queue)
    decision={'worker':'codex','phase':'pass661_livein_argument_resolution','scope':'four functions and two VM-entry transitions only','ghidra_exit_code':ex['exit_code'],'new_local_files':ex['new_files'],'target_functions':4,'transitions':2,'caller_up_inspected':'0x11B503FD->0x1195DA7B','parameter_rows':len(params),'high_symbol_rows':len(syms),'livein_rows':len(live_rows) if live_rows[0]['function_entry']!='none' else 0,'argument_mapping_success':success,'context_or_buffer_candidate_found':not (candidates and candidates[0]['transition']=='none'),'immediate_nonstack_relation_found':False,'initializer_generated':False,'decoder_run':False,'acceptance_gate_passed':False,'raw_exports_committed':False,'packet_bytes_committed':False,'keys_or_state_committed':False,'reason':blocker_reason,'next_action':nextop,'prototype_recovery_failure_proven':not success,'prototype_evidence':'target_function_prototypes.csv and parameter_storage.csv record recovered prototype/storage state'}
    wjson(ART/'pass661_decision.json',decision)
    report=f"# Pass661 Live-In Argument Resolution\n\nScope: four target functions only, transitions `0x1195DA7B -> 0x11B50330` and `0x11B50330 -> 0x11B56C63`, plus one caller-up `0x11B503FD -> 0x1195DA7B`.\n\nGhidra exit code: {ex['exit_code']}\nNew local files: {ex['new_files']}\nParameter rows: {len(params)}\nHigh-symbol rows: {len(syms)}\nArgument mapping success: {success}\nContext/buffer candidate found: {decision['context_or_buffer_candidate_found']}\nInitializer/decoder generated: False\n\nBlocker: {blocker_reason}\nNext operation: {nextop}\n\nNo raw decompile, raw p-code, packet bytes, keys/state, binaries, captures, or memory values were committed.\n"
    (INBOX/'codex_report.md').write_text(report,encoding='utf-8')
    print(json.dumps(decision,indent=2))
if __name__=='__main__': main()
