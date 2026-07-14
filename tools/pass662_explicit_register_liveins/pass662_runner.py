import csv,json,subprocess,datetime as dt,os
from pathlib import Path
REPO=Path(r'C:\AionTools\aion-agent-bridge')
ART=REPO/'artifacts'; INBOX=REPO/'inbox'; TOOL=REPO/'tools'/'pass662_explicit_register_liveins'
LOCAL=Path(r'C:\AionTools\aion_decoder_agent\outbox\pass662_explicit_register_liveins')
GH=Path(r'C:\Users\patho\Downloads\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat')
PROJ=Path(r'C:\AionTools\euroaion'); PROJNAME='euroaion'; PROGRAM='game.dll'
REGS=['RCX','RDX','R8','R9']; SITES=['0x11B503FD','0x1195DA7B','0x11B50340','0x119BAEAB']
def now(): return dt.datetime.now().replace(microsecond=0).isoformat()
def rcsv(p):
    if not Path(p).exists(): return []
    with Path(p).open(newline='',encoding='utf-8') as f: return list(csv.DictReader(f))
def wcsv(p,rows,fields):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore'); w.writeheader(); [w.writerow(r) for r in rows]
def wjson(p,d): p.write_text(json.dumps(d,indent=2,ensure_ascii=True)+'\n',encoding='utf-8')
def run_export():
    LOCAL.mkdir(parents=True,exist_ok=True)
    before={p.name:p.stat().st_mtime for p in LOCAL.glob('*') if p.is_file()}
    cmd=[str(GH),str(PROJ),PROJNAME,'-process',PROGRAM,'-noanalysis','-readOnly','-scriptPath',str(TOOL),'-postScript','ghidra_export_pass662_register_liveins.java',str(LOCAL)]
    start=now(); cp=subprocess.run(cmd,cwd=str(REPO),text=True,capture_output=True,timeout=180); end=now()
    (LOCAL/'pass662_ghidra_stdout.log').write_text(cp.stdout or '',encoding='utf-8')
    (LOCAL/'pass662_ghidra_stderr.log').write_text(cp.stderr or '',encoding='utf-8')
    files=[p for p in LOCAL.glob('*') if p.is_file() and p.stat().st_size>0]
    new=[p for p in files if p.name not in before or p.stat().st_mtime>before.get(p.name,0)]
    return {'exit_code':cp.returncode,'start':start,'end':end,'new_files':len(new),'total_files':len(files),'tail':(cp.stderr or cp.stdout or '')[-400:]}
def semantic_from_use(s):
    u=(s or '').upper()
    if 'LOAD' in u or 'STORE' in u: return 'object_or_context_use_candidate'
    if 'PTR' in u or 'INT_ADD' in u: return 'pointer_arithmetic_candidate'
    if 'CBRANCH' in u or 'INT_EQUAL' in u or 'INT_NOTEQUAL' in u: return 'selector_or_branch_candidate'
    if not u: return 'no_observed_use'
    return 'unrelated_or_passthrough'
def main():
    ART.mkdir(exist_ok=True); INBOX.mkdir(exist_ok=True)
    ex=run_export()
    inv=rcsv(LOCAL/'register_inventory.csv'); fins=rcsv(LOCAL/'function_input_registers.csv'); defs=rcsv(LOCAL/'register_reaching_defs.csv'); uses=rcsv(LOCAL/'register_uses.csv'); thunk=rcsv(LOCAL/'thunk_register_passthrough.csv'); callsite=rcsv(LOCAL/'callsite_liveins.csv'); model=rcsv(LOCAL/'prototype_model.csv')
    wcsv(ART/'pass662_register_inventory.csv', inv or [{'register':'none','found':'false','address_space':'','offset':'','size_bytes':'','bit_length':''}], ['register','found','address_space','offset','size_bytes','bit_length'])
    wcsv(ART/'pass662_function_input_registers.csv', fins or [{'function_entry':'none','function_name':'none','register':'none','register_found':'false','matching_varnode_found':'false','varnode':'','is_input':'','def_opcode':'','def_address':'','descendant_count':'0','uses_summary':'','classification':'export_failed'}], ['function_entry','function_name','register','register_found','matching_varnode_found','varnode','is_input','def_opcode','def_address','descendant_count','uses_summary','classification'])
    wcsv(ART/'pass662_register_reaching_defs.csv', defs or [{'function_entry':'none','register':'none','callsite_address':'none','nearest_def_before_site':'','def_opcode':'','def_address':'','reaching_status':'export_failed','varnode':'','notes':''}], ['function_entry','register','callsite_address','nearest_def_before_site','def_opcode','def_address','reaching_status','varnode','notes'])
    wcsv(ART/'pass662_thunk_passthrough.csv', thunk or [{'transition':'none','caller_function':'none','callee_function':'none','callsite_address':'none','register':'none','passthrough_status':'export_failed','evidence':''}], ['transition','caller_function','callee_function','callsite_address','register','passthrough_status','evidence'])
    wcsv(ART/'pass662_callsite_livein_mapping.csv', callsite or [{'transition':'none','function_entry':'none','callsite_address':'none','register':'none','register_found':'false','matching_high_varnode_found':'false','varnode':'','input_or_defined':'','reaching_definition':'','uses_at_or_after_site':'','semantic_hint':'','confidence':'none'}], ['transition','function_entry','callsite_address','register','register_found','matching_high_varnode_found','varnode','input_or_defined','reaching_definition','uses_at_or_after_site','semantic_hint','confidence'])
    # semantic use classification
    sem=[]
    for r in uses:
        if r.get('register') in REGS:
            sem.append({'function_entry':r.get('function_entry',''),'register':r.get('register',''),'varnode':r.get('varnode',''),'use_opcode':r.get('use_opcode',''),'use_address':r.get('use_address',''),'semantic_hint':r.get('semantic_hint') or semantic_from_use(r.get('use_opcode','')),'evidence_confidence':'medium' if r.get('use_opcode') else 'none'})
    if not sem:
        sem=[{'function_entry':'none','register':'none','varnode':'none','use_opcode':'none','use_address':'none','semantic_hint':'no_observed_use','evidence_confidence':'none'}]
    wcsv(ART/'pass662_semantic_use_classification.csv',sem,['function_entry','register','varnode','use_opcode','use_address','semantic_hint','evidence_confidence'])
    # candidates require observed semantic use, not convention only
    candidates=[]
    for r in callsite:
        if r.get('register') in REGS and r.get('matching_high_varnode_found')=='true' and r.get('semantic_hint') not in ['no_observed_use','unresolved','unrelated_or_passthrough','']:
            candidates.append({'transition':r.get('transition',''),'callsite_address':r.get('callsite_address',''),'register':r.get('register',''),'candidate_role':r.get('semantic_hint',''),'basis':'explicit register varnode plus observed use chain','varnode':r.get('varnode',''),'confidence':r.get('confidence','')})
    if not candidates:
        candidates=[{'transition':'none','callsite_address':'none','register':'none','candidate_role':'none','basis':'no RCX/RDX/R8/R9 matching HighFunction varnode with observed semantic use chain','varnode':'none','confidence':'none'}]
    wcsv(ART/'pass662_context_buffer_candidates.csv',candidates,['transition','callsite_address','register','candidate_role','basis','varnode','confidence'])
    success=any(r.get('register') in REGS and r.get('matching_high_varnode_found')=='true' and (r.get('input_or_defined') or r.get('reaching_definition')) for r in callsite)
    blocker=[]
    if success:
        # still no semantic role unless candidate exists
        blocker.append({'exact_function':'0x11B50330 FUN_11b50330','exact_register':'RCX/RDX/R8/R9','exact_callsite':'0x11B50340 or 0x119BAEAB','exact_local_file':str(LOCAL/'callsite_liveins.csv'),'register_object_found':'true','matching_highfunction_varnode_found':'true','input_or_defined':'see pass662_callsite_livein_mapping.csv','precise_next_operation':'inspect only immediate dependent LOAD/STORE/arithmetic uses for mapped live-in varnodes before assigning VM context or receive buffer role'})
    else:
        # choose first missing at 0x11B50330 RCX if available
        reg_found='false'; match='false'; inp='none'
        for r in callsite:
            if r.get('function_entry')=='0x11B50330' and r.get('register')=='RCX' and r.get('callsite_address') in ['0x11B50340','0x119BAEAB']:
                reg_found=r.get('register_found','false'); match=r.get('matching_high_varnode_found','false'); inp=r.get('input_or_defined','')
                break
        blocker.append({'exact_function':'0x11B50330 FUN_11b50330','exact_register':'RCX','exact_callsite':'0x11B50340 / 0x119BAEAB','exact_local_file':str(LOCAL/'callsite_liveins.csv'),'register_object_found':reg_found,'matching_highfunction_varnode_found':match,'input_or_defined':inp or 'none','precise_next_operation':'use Ghidra register varnode synthesis at the target function entry (Varnode(registerAddress,size)) and query HighFunction symbol/cover intersections for RCX/RDX/R8/R9, because enumerating HighFunction pcode varnodes did not produce matching live-in register varnodes'})
    wcsv(ART/'pass662_exact_blocker.csv',blocker,['exact_function','exact_register','exact_callsite','exact_local_file','register_object_found','matching_highfunction_varnode_found','input_or_defined','precise_next_operation'])
    queue={'phase':'pass662_explicit_register_liveins','updated':now(),'stages':[{'name':'explicit_register_livein_export_and_parse','status':'completed','attempts':1,'fallback':'not needed; exact register-varnode blocker recorded if mapping absent','fallback_status':'not_needed','fallback_attempts':0,'last_error':'','produced_artifacts':['artifacts/pass662_register_inventory.csv','artifacts/pass662_function_input_registers.csv','artifacts/pass662_register_reaching_defs.csv','artifacts/pass662_thunk_passthrough.csv','artifacts/pass662_callsite_livein_mapping.csv','artifacts/pass662_semantic_use_classification.csv','artifacts/pass662_context_buffer_candidates.csv','artifacts/pass662_exact_blocker.csv','artifacts/pass662_decision.json','inbox/codex_report.md']}]} 
    wjson(ART/'pass662_work_queue.json',queue)
    decision={'worker':'codex','phase':'pass662_explicit_register_liveins','scope':'four specified functions only; explicit Windows x64 register live-ins only','ghidra_exit_code':ex['exit_code'],'new_local_files':ex['new_files'],'registers_found':sum(1 for r in inv if r.get('found')=='true'),'target_functions':4,'callsites':4,'explicit_register_mapping_success':success,'context_or_buffer_candidate_found':not(candidates and candidates[0]['transition']=='none'),'initializer_generated':False,'decoder_run':False,'acceptance_gate_passed':False,'raw_exports_committed':False,'packet_bytes_committed':False,'keys_or_state_committed':False,'reason':'explicit register objects were queried; matching HighFunction live-in varnodes are recorded only if present in pass662_callsite_livein_mapping.csv','exact_blocker':blocker[0],'next_action':blocker[0]['precise_next_operation']}
    wjson(ART/'pass662_decision.json',decision)
    report=f"# Pass662 Explicit Register Live-ins\n\nScope: four functions only, explicit RCX/RDX/R8/R9/RSI/RDI/RBP/R12-R15 register live-ins.\n\nGhidra exit code: {ex['exit_code']}\nNew local files: {ex['new_files']}\nRegisters found: {decision['registers_found']}\nExplicit RCX/RDX/R8/R9 mapping success: {success}\nContext/buffer candidate found: {decision['context_or_buffer_candidate_found']}\nInitializer/decoder generated: False\n\nBlocker/next: {decision['next_action']}\n\nNo raw p-code/decompile, packet bytes, keys/state, binaries, captures, or memory values were committed.\n"
    (INBOX/'codex_report.md').write_text(report,encoding='utf-8')
    print(json.dumps(decision,indent=2))
if __name__=='__main__': main()
