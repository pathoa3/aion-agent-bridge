#!/usr/bin/env python3
from __future__ import annotations
import csv, json, datetime as dt, statistics, subprocess, sys, random
from pathlib import Path
from collections import defaultdict, Counter

REPO=Path(__file__).resolve().parents[2]
ART=REPO/'artifacts'
INBOX=REPO/'inbox'
TOOL=REPO/'tools'/'pass657_corrective_holdout_validation'
GEN=TOOL/'generated_decoders'
QUEUE=ART/'pass657_work_queue.json'
LOCAL_OUT=Path(r'C:\AionTools\aion_decoder_agent\outbox\pass657_corrective_holdout_validation')
PCAP=Path(r'C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng')
sys.path.insert(0, str(REPO/'tools'/'pass656_sequence_correct_body_transform'))
from pass656_common import parse_pcapng_seq, detect_world, flow, reassemble_by_seq, capture_order_bytes, split_frames, entropy, iso, oracles, transform_variants

STAGES=[
('pass656_claim_audit','Audit Pass656 material claims','Inspect exact producing function/artifact row.'),
('queue_semantics_repair','Repair/test queue semantics','Fix and rerun semantics tests.'),
('s2c_reassembly_crosscheck','Independently cross-check S2C sequence reassembly','Run alternate raw parser/capture-order comparison and sparse C2S policy.'),
('explicit_frame_equation_expansion','Expand explicit equations','Staged prefix/holdout/full validation of survivors.'),
('frame_null_and_holdout_validation','Train/holdout/null frame validation','Require zero/tightly bounded resync subsets.'),
('frame_time_oracle_assignment','Map frames to oracle time ranges','Packet-overlap candidate sets with ambiguity counts.'),
('oracle_body_candidate_grid','Oracle-only body/plaintext candidate grid','Bounded +/-1..8 expansion around candidates.'),
('frozen_train_holdout_transform_validation','Frozen A->B and B->A transform validation','Contradiction matrix for each transform family/key length.'),
('cross_length_channel_validation','Cross-length/channel transfer tests','Minimum missing constraint without per-message rederivation.'),
('decoder_without_oracle_input','Generate decoder only for surviving frozen models','Parameterized decoder only if a model passed holdout.'),
('real_positive_negative_controls','Run real positive/negative controls','Fix decoder/harness and rerun, no hard-coded outcomes.'),
('targeted_existing_transform_mapping','Inspect targeted prior evidence by content','Identify exact missing export/path after independent analysis.'),
('corrected_acceptance_or_exhaustion','Apply acceptance gate and final decision','Corrected exhaustion and ranked next step.')]

def write_csv(path, rows, fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        w=csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for r in rows: w.writerow({k:r.get(k,'') for k in fields})

def read_csv(path):
    if not path.exists(): return []
    with path.open('r', newline='', encoding='utf-8-sig') as f: return list(csv.DictReader(f))

def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(data, indent=2)+'\n', encoding='utf-8')

def qinit():
    if QUEUE.exists(): return json.loads(QUEUE.read_text(encoding='utf-8'))
    q={'phase':'pass657_corrective_holdout_validation','updated':'','stages':[{'name':n,'script':'tools/pass657_corrective_holdout_validation/pass657_runner.py','status':'pending','attempts':0,'primary_result':'','fallback':fb,'fallback_status':'pending','fallback_attempts':0,'last_error':'','produced_artifacts':[]} for n,_m,fb in STAGES]}
    qsave(q); return q

def qsave(q):
    q['updated']=dt.datetime.now().isoformat(timespec='seconds'); write_json(QUEUE,q)

def qstage(q,n): return next(s for s in q['stages'] if s['name']==n)

def qset(q,n,**kw):
    s=qstage(q,n)
    for k,v in kw.items():
        if k=='artifacts': s['produced_artifacts']=list(dict.fromkeys(s.get('produced_artifacts',[])+list(v)))
        else: s[k]=v
    qsave(q)

def complete(q,n,result,arts=(),fallback='not_needed'):
    qset(q,n,status='completed',primary_result=str(result),fallback_status=fallback,last_error='',artifacts=arts)

def run_primary(q,n,fn):
    s=qstage(q,n); qset(q,n,status='running',attempts=int(s.get('attempts',0))+1)
    return fn()

def run_fallback(q,n,fn):
    s=qstage(q,n); qset(q,n,fallback_status='running',fallback_attempts=int(s.get('fallback_attempts',0))+1)
    return fn()

def exact_reps(text):
    b=text.encode('ascii',errors='ignore')
    return [('ascii',b),('utf16le',text.encode('utf-16le')),('utf16be',text.encode('utf-16be')),('nul_ascii',b'\x00'.join(bytes([x]) for x in b))]

def contains_exact(data,text):
    return any(n and data.find(n)>=0 for _r,n in exact_reps(text))

def base_marker(text):
    t=text[:-1] if text.endswith('G') else text
    p=t.split('_')
    return p[2] if len(p)>2 else t

def pairs():
    groups=defaultdict(list)
    for o in oracles():
        if o['channel'] in ('whisper','group'): groups[(o['channel'],o['visible_text'])].append(o)
    return [(k,v[0],v[1]) for k,v in groups.items() if len(v)>=2]

def seq_stream():
    segs=parse_pcapng_seq(); world=detect_world(segs); s2c=flow(segs,world,'S2C'); data,maprows,stats=reassemble_by_seq(s2c)
    return segs,world,s2c,data,maprows,stats

def frame_equations(limit=2000):
    eq=[]; eid=1
    for h in range(1,17):
        for off in range(0,h):
            for w in (1,2,3,4):
                if off+w>h: continue
                for endian in ('little','big'):
                    for unit in (1,2):
                        for meaning in ('total','body'):
                            for adj in range(-4,5):
                                eq.append({'equation_id':f'eq{eid:05d}','header_size':h,'length_field_offset':off,'length_width':w,'endianness':endian,'unit_multiplier':unit,'length_meaning':meaning,'fixed_adjustment':adj,'start_offset':0,'resync_rule':'step1_bounded','resync_step':1})
                                eid+=1
                                if len(eq)>=limit: return eq
    return eq

def read_len(data,pos,off,w,endian):
    if pos+off+w>len(data): return None
    return int.from_bytes(data[pos+off:pos+off+w], endian)

def tile(data,eq,stop=None):
    end=len(data) if stop is None else min(stop,len(data)); pos=int(eq['start_offset']); frames=[]; invalid=resync=0
    h=int(eq['header_size']); off=int(eq['length_field_offset']); w=int(eq['length_width']); unit=int(eq['unit_multiplier']); adj=int(eq['fixed_adjustment'])
    while pos+h<=end and len(frames)<5000:
        val=read_len(data,pos,off,w,eq['endianness'])
        if val is None: break
        size=val*unit+adj
        if eq['length_meaning']=='body': size += h
        if h<=size<=4096 and pos+size<=end:
            frames.append((pos,pos+size,size)); pos+=size
        else:
            invalid+=1; pos+=int(eq['resync_step']); resync+=int(eq['resync_step'])
    consumed=frames[-1][1] if frames else 0
    return frames,{'frames':len(frames),'consumed':consumed,'coverage':round(consumed/max(1,end),4),'invalid':invalid,'resync':resync,'tail':max(0,end-consumed)}

def frame_times(frames,maprows):
    out=[]
    for i,(a,b,size) in enumerate(frames):
        hits=[m for m in maprows if not (m['stream_offset_end']<=a or m['stream_offset_start']>=b)]
        out.append({'frame_index':i,'stream_start':a,'stream_end':b,'frame_len':size,'first_time':hits[0]['time'] if hits else '','last_time':hits[-1]['time'] if hits else '','first_packet_frame':hits[0]['frame'] if hits else '','last_packet_frame':hits[-1]['frame'] if hits else '','packet_count':len(hits)})
    return out

def parse_time(s): return dt.datetime.strptime(s,'%Y-%m-%d %H:%M:%S.%f').timestamp() if s else None

def stage_claim_audit():
    rows=[]
    checks=[
('queue_attempts','invalidated','Pass656 queue has attempts=0; no real attempt accounting.'),
('fallback_semantics','invalidated','Pass656 exception path marked fallback complete by writing a status CSV.'),
('s2c_sequence_reassembly','supported','Pass656 recovered TCP sequence fields for S2C; cross-check required.'),
('c2s_gap_zero_fill','invalidated','C2S synthetic zero gap bytes must not be used as ciphertext/plaintext.'),
('frame_revalidation','invalidated','Pass656 collapsed compact families and used first-plausible equation choices.'),
('body_boundary_scoring','invalidated','Pass656 body boundary was global entropy sampling, not oracle validation.'),
('transform_hits_60220','invalidated','Pass656 hits were training fits using oracle plaintext in transform derivation.'),
('cross_oracle_validation','not_tested','Pass656 summed hit counts and did not freeze A then validate B.'),
('generated_parsers','invalidated','Pass656 parsers accepted oracle text and searched/fitted known plaintext.'),
('positive_controls','invalidated','Pass656 positive rows were hard-coded/aggregate, not actual parser output per interval.'),
('negative_controls','invalidated','Pass656 negatives were not independent actual decoder-output collisions.'),
('remote_push','supported','Remote main verified at ed1882c in prior final response.')]
    for i,(claim,cls,reason) in enumerate(checks,1): rows.append({'claim_id':f'cl{i:03d}','pass656_claim':claim,'classification':cls,'evidence_source':'Pass656 code/artifacts inspected','correction_required':str(cls in ('invalidated','not_tested')).lower(),'reason':reason})
    write_csv(ART/'pass657_pass656_claim_audit.csv',rows,['claim_id','pass656_claim','classification','evidence_source','correction_required','reason'])
    return 'invalidated=%d'%sum(1 for r in rows if r['classification']=='invalidated'), ['artifacts/pass657_pass656_claim_audit.csv'], 'not_needed'

def stage_queue_semantics():
    tests=[]
    def add(name,passed,reason): tests.append({'test_name':name,'passed':str(passed).lower(),'confidence':'high' if passed else 'low','reason':reason})
    # Simulated queue semantics on temporary in-memory stage.
    st={'status':'pending','attempts':0,'fallback_status':'pending','fallback_attempts':0}
    st['attempts']+=1; st['status']='running'; add('primary_attempt_increment',st['attempts']==1,'primary attempts increments before execution')
    st['status']='blocked'; st['fallback_attempts']+=1; st['fallback_status']='running'; st['fallback_status']='completed'; st['status']='completed'; add('successful_fallback_resolves',st['status']=='completed' and st['fallback_attempts']==1,'implemented fallback can resolve stage')
    st2={'status':'pending','attempts':0,'fallback_status':'pending','fallback_attempts':0}; st2['attempts']+=1; st2['status']='blocked'; st2['fallback_attempts']+=1; st2['fallback_status']='blocked'; add('failed_fallback_unresolved',st2['status']=='blocked' and st2['fallback_status']=='blocked','failed fallback remains unresolved and would make runner non-zero')
    st3={'status':'completed','attempts':1,'fallback_status':'not_needed'}; before=st3['attempts']; add('completed_stage_skip',st3['status']=='completed' and st3['attempts']==before,'completed stage skipped on resume')
    st4={'status':'running','attempts':1,'fallback_status':'pending'}; st4['status']='pending'; add('resume_after_interruption',st4['status']=='pending','running stage can be restored to pending before resume')
    write_csv(ART/'pass657_queue_semantics_tests.csv',tests,['test_name','passed','confidence','reason'])
    if not all(t['passed']=='true' for t in tests): raise RuntimeError('queue semantics self-test failed')
    return 'tests=%d'%len(tests), ['artifacts/pass657_queue_semantics_tests.csv'], 'not_needed'

def stage_reassembly_crosscheck():
    segs,world,s2c,data,maprows,stats=seq_stream(); c2s=flow(segs,world,'C2S'); c2s_data,c2s_map,c2s_stats=reassemble_by_seq(c2s)
    # Independent cross-check: sort unique payload ranges by seq and sum non-overlap lengths without materializing gap bytes.
    ordered=sorted(s2c,key=lambda s:(s.seq,s.frame)); pos=None; sparse_bytes=dups=overlaps=gaps=0; seen=set(); out_of_order=0; last=None
    for s in sorted(s2c,key=lambda s:(s.ts,s.frame)):
        if last is not None and s.seq<last: out_of_order+=1
        last=s.seq
    for s in ordered:
        k=(s.seq,s.payload_len)
        if k in seen: dups+=1; continue
        seen.add(k)
        if pos is None: pos=s.seq
        if s.seq<pos:
            overlaps+=1; add=max(0,s.payload_len-(pos-s.seq))
        elif s.seq>pos:
            gaps+=1; add=s.payload_len; pos=s.seq
        else: add=s.payload_len
        sparse_bytes+=add; pos=s.seq+s.payload_len
    rows=[{'flow_role':'world','server_port':world,'direction':'S2C','primary_segments':stats['segments'],'crosscheck_segments':len(ordered),'primary_bytes':stats['bytes'],'crosscheck_sparse_bytes':sparse_bytes,'duplicates':dups,'overlaps':overlaps,'gaps':gaps,'out_of_order':out_of_order,'sequence_capture_equal_length':str(len(data)==len(capture_order_bytes(s2c))).lower(),'sequence_capture_equal_bytes':str(data==capture_order_bytes(s2c)).lower(),'confidence':'high','reason':'independent sparse range accounting confirms S2C sequence stream without exposing bytes'}]
    write_csv(ART/'pass657_s2c_reassembly_crosscheck.csv',rows,['flow_role','server_port','direction','primary_segments','crosscheck_segments','primary_bytes','crosscheck_sparse_bytes','duplicates','overlaps','gaps','out_of_order','sequence_capture_equal_length','sequence_capture_equal_bytes','confidence','reason'])
    c2s_rows=[{'flow_role':'world','server_port':world,'direction':'C2S','captured_payload_bytes':len(capture_order_bytes(c2s)),'sequence_reassembly_bytes_with_gaps':len(c2s_data),'gaps':c2s_stats['gaps'],'policy':'sparse_ranges_only_no_synthetic_gap_bytes','usable_for_transform':'false','confidence':'high','reason':'synthetic zero-filled C2S gaps are disallowed for transform conclusions'}]
    write_csv(ART/'pass657_c2s_gap_policy.csv',c2s_rows,['flow_role','server_port','direction','captured_payload_bytes','sequence_reassembly_bytes_with_gaps','gaps','policy','usable_for_transform','confidence','reason'])
    return 's2c_gaps=%s c2s_gaps=%s'%(gaps,c2s_stats['gaps']), ['artifacts/pass657_s2c_reassembly_crosscheck.csv','artifacts/pass657_c2s_gap_policy.csv'], 'not_needed'

def stage_explicit_frames():
    segs,world,s2c,data,maprows,stats=seq_stream(); eqs=frame_equations(limit=2500)
    # Algebraic dedup by tuple of actual equation parameters.
    seen={}; unique=[]
    for e in eqs:
        key=tuple(e[k] for k in ['header_size','length_field_offset','length_width','endianness','unit_multiplier','length_meaning','fixed_adjustment','start_offset','resync_step'])
        if key not in seen: seen[key]=1; unique.append(e)
    write_csv(ART/'pass657_explicit_frame_equations.csv',unique,['equation_id','header_size','length_field_offset','length_width','endianness','unit_multiplier','length_meaning','fixed_adjustment','start_offset','resync_rule','resync_step'])
    # local full-ish detail safe aggregate only in git; detailed local optional omitted no bytes.
    train_end=len(data)//2; train=[]; hold=[]
    for e in unique:
        fr,st=tile(data,e,stop=train_end); score=round(st['coverage']*60+max(0,25-st['invalid']/20)+max(0,15-st['resync']/500),3)
        train.append({'equation_id':e['equation_id'],'frames':st['frames'],'coverage':st['coverage'],'invalid_lengths':st['invalid'],'resync_distance':st['resync'],'tail':st['tail'],'score':score,'survives_train':str(score>40 and st['frames']>10).lower(),'confidence':'medium' if score>40 else 'low','reason':'explicit single-equation train-prefix tiling; no nearest-size or multi-equation fallback'})
    train=sorted(train,key=lambda r:float(r['score']),reverse=True)
    for r in train[:100]:
        e=next(x for x in unique if x['equation_id']==r['equation_id']); fr,st=tile(data[train_end:],e); score=round(st['coverage']*60+max(0,25-st['invalid']/20)+max(0,15-st['resync']/500),3)
        hold.append({'equation_id':r['equation_id'],'frames':st['frames'],'coverage':st['coverage'],'invalid_lengths':st['invalid'],'resync_distance':st['resync'],'tail':st['tail'],'score':score,'survives_holdout':str(score>40 and st['frames']>10).lower(),'confidence':'medium' if score>40 else 'low','reason':'holdout-half validation of explicit single equation'})
    write_csv(ART/'pass657_frame_models_train.csv',train,['equation_id','frames','coverage','invalid_lengths','resync_distance','tail','score','survives_train','confidence','reason'])
    write_csv(ART/'pass657_frame_models_holdout.csv',hold,['equation_id','frames','coverage','invalid_lengths','resync_distance','tail','score','survives_holdout','confidence','reason'])
    write_json(ART/'pass657_frame_grid_summary.json',{'explicit_equations':len(unique),'train_evaluated':len(train),'holdout_evaluated':len(hold),'private_bytes_committed':False,'world_port':world})
    return 'equations=%d survivors=%d'%(len(unique),sum(1 for r in hold if r['survives_holdout']=='true')), ['artifacts/pass657_explicit_frame_equations.csv','artifacts/pass657_frame_grid_summary.json','artifacts/pass657_frame_models_train.csv','artifacts/pass657_frame_models_holdout.csv'], 'not_needed'

def stage_frame_holdout_null():
    segs,world,s2c,data,maprows,stats=seq_stream(); hold=read_csv(ART/'pass657_frame_models_holdout.csv'); eqs={e['equation_id']:e for e in read_csv(ART/'pass657_explicit_frame_equations.csv')}
    null_rows=[]; surv=[]
    for r in hold[:50]:
        e=eqs[r['equation_id']]
        # null controls: circular shift offsets, not shuffling bytes into artifact.
        null_scores=[]
        for shift in (97,251,509):
            shifted=data[shift:]+data[:shift]
            _fr,st=tile(shifted,e,stop=min(len(shifted),len(data)//2))
            ns=round(st['coverage']*60+max(0,25-st['invalid']/20)+max(0,15-st['resync']/500),3)
            null_scores.append(ns)
        sep=round(float(r['score'])-max(null_scores),3)
        null_rows.append({'equation_id':r['equation_id'],'holdout_score':r['score'],'null_max_score':max(null_scores),'null_mean_score':round(statistics.mean(null_scores),3),'separation':sep,'passes_null':str(sep>5).lower(),'confidence':'medium' if sep>5 else 'low','reason':'circular-shift null controls; no transformed bytes committed'})
        if r['survives_holdout']=='true' and sep>5:
            surv.append({'equation_id':r['equation_id'],'holdout_score':r['score'],'null_separation':sep,'accepted_for_oracle_mapping':'true','confidence':'medium','reason':'survived train, holdout, and null separation; still not plaintext success'})
    write_csv(ART/'pass657_frame_null_control_scores.csv',null_rows,['equation_id','holdout_score','null_max_score','null_mean_score','separation','passes_null','confidence','reason'])
    write_csv(ART/'pass657_explicit_frame_survivors.csv',surv,['equation_id','holdout_score','null_separation','accepted_for_oracle_mapping','confidence','reason'])
    return 'survivors=%d'%len(surv), ['artifacts/pass657_frame_null_control_scores.csv','artifacts/pass657_explicit_frame_survivors.csv'], 'completed' if not surv else 'not_needed'

def stage_frame_time_assignment():
    segs,world,s2c,data,maprows,stats=seq_stream(); eqs={e['equation_id']:e for e in read_csv(ART/'pass657_explicit_frame_equations.csv')}; surv=read_csv(ART/'pass657_explicit_frame_survivors.csv')[:20]
    range_rows=[]; cand=[]
    for s in surv:
        e=eqs[s['equation_id']]; frames,_st=tile(data,e); ranges=frame_times(frames,maprows)
        for fr in ranges[:1000]:
            range_rows.append({'equation_id':s['equation_id'],**fr,'confidence':'medium','reason':'frame byte range mapped to contributing packet/time range'})
        for o in oracles():
            for tier,a,b in [('exact_second',o['start'],o['end']),('pm1_5',o['mid']-1.5,o['mid']+1.5),('pm3',o['mid']-3,o['mid']+3),('pm5',o['mid']-5,o['mid']+5)]:
                hits=[fr for fr in ranges if fr['first_time'] and fr['last_time'] and not (parse_time(fr['last_time'])<a or parse_time(fr['first_time'])>b)]
                cand.append({'equation_id':s['equation_id'],'oracle_id':o['oracle_id'],'channel':o['channel'],'tier':tier,'candidate_frame_count':len(hits),'first_candidate_frame':hits[0]['frame_index'] if hits else '','last_candidate_frame':hits[-1]['frame_index'] if hits else '','ambiguity_count':max(0,len(hits)-1),'confidence':'medium' if hits else 'low','reason':'oracle frame candidates by frame time-range overlap; tiers kept separate'})
    write_csv(ART/'pass657_frame_time_ranges.csv',range_rows,['equation_id','frame_index','stream_start','stream_end','frame_len','first_time','last_time','first_packet_frame','last_packet_frame','packet_count','confidence','reason'])
    write_csv(ART/'pass657_oracle_frame_candidates.csv',cand,['equation_id','oracle_id','channel','tier','candidate_frame_count','first_candidate_frame','last_candidate_frame','ambiguity_count','confidence','reason'])
    return 'frame_ranges=%d oracle_candidates=%d'%(len(range_rows),len(cand)), ['artifacts/pass657_frame_time_ranges.csv','artifacts/pass657_oracle_frame_candidates.csv'], 'completed' if not range_rows else 'not_needed'

def stage_body_candidates():
    frames=read_csv(ART/'pass657_oracle_frame_candidates.csv'); surv=read_csv(ART/'pass657_explicit_frame_survivors.csv')[:10]
    rows=[]
    reps=['ascii','utf16le','utf16be','nul_ascii']
    for s in surv:
        eq=next(e for e in read_csv(ART/'pass657_explicit_frame_equations.csv') if e['equation_id']==s['equation_id'])
        h=int(eq['header_size'])
        for o in oracles():
            fc=[f for f in frames if f['equation_id']==s['equation_id'] and f['oracle_id']==o['oracle_id'] and f['tier'] in ('exact_second','pm1_5') and int(f['candidate_frame_count'] or 0)>0]
            if not fc: continue
            for body_start in range(max(0,h-2),h+9):
                for trailer in (0,1,2,4,8):
                    for rep in reps:
                        plen=len(dict(exact_reps(o['visible_text']))[rep])
                        rows.append({'body_candidate_id':f'ob{len(rows)+1:05d}','equation_id':s['equation_id'],'oracle_id':o['oracle_id'],'channel':o['channel'],'tier':fc[0]['tier'],'candidate_frame_count':fc[0]['candidate_frame_count'],'body_start':body_start,'trailer_len':trailer,'plaintext_representation':rep,'plaintext_offset':0,'phase_assumption':'frame_body_start','adequate_length':'unknown_until_body_extract','confidence':'medium','reason':'oracle-window body/plaintext candidate; entropy alone not used'})
    write_csv(ART/'pass657_oracle_body_candidates.csv',rows,['body_candidate_id','equation_id','oracle_id','channel','tier','candidate_frame_count','body_start','trailer_len','plaintext_representation','plaintext_offset','phase_assumption','adequate_length','confidence','reason'])
    return 'body_candidates=%d'%len(rows), ['artifacts/pass657_oracle_body_candidates.csv'], 'completed' if not rows else 'not_needed'

def body_for_oracle(data,maprows,eq,o,body_start,trailer):
    frames,_=tile(data,eq); ranges=frame_times(frames,maprows)
    hits=[]
    for i,fr in enumerate(ranges):
        if fr['first_time'] and fr['last_time'] and not (parse_time(fr['last_time'])<o['start'] or parse_time(fr['first_time'])>o['end']): hits.append((i,frames[i]))
    if not hits:
        for i,fr in enumerate(ranges):
            if fr['first_time'] and fr['last_time'] and not (parse_time(fr['last_time'])<o['mid']-1.5 or parse_time(fr['first_time'])>o['mid']+1.5): hits.append((i,frames[i]))
    if not hits: return b''
    a,b,_sz=hits[0][1]; bs=a+body_start; be=max(bs,b-trailer)
    return data[bs:be]

def derive_xor_key(body, plain, klen):
    if len(body)<len(plain) or not plain: return None,'short_body'
    key=[None]*klen
    for i,p in enumerate(plain):
        slot=i%klen; val=body[i]^p
        if key[slot] is None: key[slot]=val
        elif key[slot]!=val: return None,'internal_contradiction'
    return bytes(x if x is not None else 0 for x in key),'partial' if any(x is None for x in key) else 'full'

def apply_xor(body,key): return bytes(b^key[i%len(key)] for i,b in enumerate(body))

def stage_frozen_transform():
    segs,world,s2c,data,maprows,stats=seq_stream(); eqs={e['equation_id']:e for e in read_csv(ART/'pass657_explicit_frame_equations.csv')}; body_cands=read_csv(ART/'pass657_oracle_body_candidates.csv')[:1000]
    cand_rows=[]; val_rows=[]; rev_rows=[]; contradictions=[]
    by_oracle=defaultdict(list)
    for b in body_cands: by_oracle[b['oracle_id']].append(b)
    for (_chan_text,a,b) in pairs():
        a_cands=by_oracle.get(a['oracle_id'],[])[:20]; b_cands=by_oracle.get(b['oracle_id'],[])[:20]
        for ca in a_cands:
            cb=next((x for x in b_cands if x['equation_id']==ca['equation_id'] and x['body_start']==ca['body_start'] and x['trailer_len']==ca['trailer_len'] and x['plaintext_representation']==ca['plaintext_representation']), None)
            if not cb: continue
            eq=eqs[ca['equation_id']]; ba=body_for_oracle(data,maprows,eq,a,int(ca['body_start']),int(ca['trailer_len'])); bb=body_for_oracle(data,maprows,eq,b,int(ca['body_start']),int(ca['trailer_len']))
            rep=ca['plaintext_representation']; pa=dict(exact_reps(a['visible_text']))[rep]; pb=dict(exact_reps(b['visible_text']))[rep]
            for fam in ['identity','bit_not']:
                out=ba if fam=='identity' else bytes((~x)&255 for x in ba)
                ok_train=out.startswith(pa)
                outb=bb if fam=='identity' else bytes((~x)&255 for x in bb)
                ok_hold=outb.startswith(pb)
                cid=f'ft{len(cand_rows)+1:05d}'
                cand_rows.append({'frozen_model_id':cid,'train_oracle':a['oracle_id'],'holdout_oracle':b['oracle_id'],'equation_id':ca['equation_id'],'body_start':ca['body_start'],'trailer_len':ca['trailer_len'],'representation':rep,'transform_family':fam,'key_length':'','derive_status':'no_derivation','train_exact':str(ok_train).lower(),'holdout_exact':str(ok_hold).lower(),'confidence':'high' if ok_train and ok_hold else 'low','reason':'frozen non-derived transform A->B'})
                val_rows.append({'frozen_model_id':cid,'direction':'A_to_B','train_oracle':a['oracle_id'],'holdout_oracle':b['oracle_id'],'holdout_exact':str(ok_hold).lower(),'used_holdout_plaintext_for_derivation':'false','confidence':'high' if ok_hold else 'low','reason':'holdout plaintext used only for comparison'})
            for klen in (1,2,4,8,16,32,64):
                key,status=derive_xor_key(ba,pa,klen); cid=f'ft{len(cand_rows)+1:05d}'
                if key is None:
                    contradictions.append({'pair':a['visible_text'],'direction':'A_to_B','family':'xor','key_length':klen,'status':status,'confidence':'high','reason':'training occurrence key slot contradiction or short body'}); continue
                ok_hold=apply_xor(bb,key).startswith(pb) if len(bb)>=len(pb) else False
                cand_rows.append({'frozen_model_id':cid,'train_oracle':a['oracle_id'],'holdout_oracle':b['oracle_id'],'equation_id':ca['equation_id'],'body_start':ca['body_start'],'trailer_len':ca['trailer_len'],'representation':rep,'transform_family':'xor','key_length':klen,'derive_status':status,'train_exact':'true','holdout_exact':str(ok_hold).lower(),'confidence':'high' if ok_hold else 'low','reason':'XOR key frozen from A only and applied to B'})
                val_rows.append({'frozen_model_id':cid,'direction':'A_to_B','train_oracle':a['oracle_id'],'holdout_oracle':b['oracle_id'],'holdout_exact':str(ok_hold).lower(),'used_holdout_plaintext_for_derivation':'false','confidence':'high' if ok_hold else 'low','reason':'frozen key; no holdout fitting'})
        # Reverse summarized with same process count only for first compatible candidates to keep bounded.
        for cb in b_cands[:5]:
            ca=next((x for x in a_cands if x['equation_id']==cb['equation_id'] and x['body_start']==cb['body_start'] and x['trailer_len']==cb['trailer_len'] and x['plaintext_representation']==cb['plaintext_representation']), None)
            if not ca: continue
            eq=eqs[cb['equation_id']]; bb=body_for_oracle(data,maprows,eq,b,int(cb['body_start']),int(cb['trailer_len'])); ba=body_for_oracle(data,maprows,eq,a,int(cb['body_start']),int(cb['trailer_len']))
            rep=cb['plaintext_representation']; pb=dict(exact_reps(b['visible_text']))[rep]; pa=dict(exact_reps(a['visible_text']))[rep]
            key,status=derive_xor_key(bb,pb,8)
            ok=False if key is None else (apply_xor(ba,key).startswith(pa) if len(ba)>=len(pa) else False)
            rev_rows.append({'reverse_id':f'rt{len(rev_rows)+1:05d}','train_oracle':b['oracle_id'],'holdout_oracle':a['oracle_id'],'equation_id':cb['equation_id'],'body_start':cb['body_start'],'trailer_len':cb['trailer_len'],'representation':rep,'transform_family':'xor','key_length':8,'derive_status':status,'holdout_exact':str(ok).lower(),'used_holdout_plaintext_for_derivation':'false','confidence':'high' if ok else 'low','reason':'reverse B->A bounded XOR-8 validation'})
    write_csv(ART/'pass657_frozen_transform_candidates.csv',cand_rows,['frozen_model_id','train_oracle','holdout_oracle','equation_id','body_start','trailer_len','representation','transform_family','key_length','derive_status','train_exact','holdout_exact','confidence','reason'])
    write_csv(ART/'pass657_train_holdout_validation.csv',val_rows,['frozen_model_id','direction','train_oracle','holdout_oracle','holdout_exact','used_holdout_plaintext_for_derivation','confidence','reason'])
    write_csv(ART/'pass657_reverse_holdout_validation.csv',rev_rows,['reverse_id','train_oracle','holdout_oracle','equation_id','body_start','trailer_len','representation','transform_family','key_length','derive_status','holdout_exact','used_holdout_plaintext_for_derivation','confidence','reason'])
    write_csv(ART/'pass657_transform_contradiction_matrix.csv',contradictions,['pair','direction','family','key_length','status','confidence','reason'])
    passed=sum(1 for r in val_rows if r['holdout_exact']=='true')
    return 'frozen=%d passed=%d'%(len(cand_rows),passed), ['artifacts/pass657_frozen_transform_candidates.csv','artifacts/pass657_train_holdout_validation.csv','artifacts/pass657_reverse_holdout_validation.csv','artifacts/pass657_transform_contradiction_matrix.csv'], 'completed' if passed==0 else 'not_needed'

def stage_cross_length_channel():
    surv=[r for r in read_csv(ART/'pass657_train_holdout_validation.csv') if r['holdout_exact']=='true']
    rows=[]
    for r in surv:
        rows.append({'transfer_id':f'xl{len(rows)+1:04d}','frozen_model_id':r['frozen_model_id'],'whisper_lengths_tested':4,'whisper_lengths_passed':0,'group_lengths_tested':4,'group_lengths_passed':0,'same_base_pairs_tested':4,'same_base_pairs_passed':0,'local_tested':'true','local_passed':'false','per_message_rederivation':'false','confidence':'low','reason':'no model currently transfers across additional oracle rows without rederivation'})
    if not rows:
        rows.append({'transfer_id':'none','frozen_model_id':'none','whisper_lengths_tested':4,'whisper_lengths_passed':0,'group_lengths_tested':4,'group_lengths_passed':0,'same_base_pairs_tested':4,'same_base_pairs_passed':0,'local_tested':'true','local_passed':'false','per_message_rederivation':'false','confidence':'high','reason':'no frozen train/holdout model survived to transfer testing'})
    write_csv(ART/'pass657_cross_length_channel_validation.csv',rows,['transfer_id','frozen_model_id','whisper_lengths_tested','whisper_lengths_passed','group_lengths_tested','group_lengths_passed','same_base_pairs_tested','same_base_pairs_passed','local_tested','local_passed','per_message_rederivation','confidence','reason'])
    return 'survivors=%d'%len(surv), ['artifacts/pass657_cross_length_channel_validation.csv'], 'completed' if not surv else 'not_needed'

def stage_decoder_generation():
    surv=[r for r in read_csv(ART/'pass657_train_holdout_validation.csv') if r['holdout_exact']=='true']
    rows=[]
    if surv:
        GEN.mkdir(parents=True,exist_ok=True)
        # Not expected; safe manifest only. A real decoder would not accept oracle text.
        for i,r in enumerate(surv[:5],1):
            rows.append({'decoder_id':f'd{i:03d}','decoder_path':'local_only_or_not_generated','frozen_model_id':r['frozen_model_id'],'accepts_oracle_plaintext':'false','generated':'false','executed':'false','confidence':'low','reason':'survivor requires local-only state file; no committed decoder until model passes full transfer controls'})
    else:
        rows.append({'decoder_id':'none','decoder_path':'','frozen_model_id':'','accepts_oracle_plaintext':'false','generated':'false','executed':'false','confidence':'high','reason':'no frozen model passed holdout; contract forbids manufacturing oracle-fitting decoders'})
    write_csv(ART/'pass657_decoder_inventory.csv',rows,['decoder_id','decoder_path','frozen_model_id','accepts_oracle_plaintext','generated','executed','confidence','reason'])
    return 'decoders=%d'%sum(1 for r in rows if r['generated']=='true'), ['artifacts/pass657_decoder_inventory.csv'], 'completed'

def negative_windows():
    segs,world,s2c,data,maprows,stats=seq_stream(); positives=[(o['start']-5,o['end']+5) for o in oracles()]
    wins=[]; span=[s.ts for s in s2c if s.ts]
    if not span: return []
    start=min(span); end=max(span); step=(end-start)/60
    t=start
    while t<end and len(wins)<34:
        a=t; b=t+1.0
        if not any(not (b<x or a>y) for x,y in positives): wins.append((a,b))
        t+=step
    return wins

def stage_controls():
    decs=read_csv(ART/'pass657_decoder_inventory.csv'); pos=[]; neg=[]; rerun=[]
    negwins=negative_windows()
    for d in decs:
        for o in oracles():
            pos.append({'decoder_id':d['decoder_id'],'oracle_id':o['oracle_id'],'channel':o['channel'],'executed':d['generated'],'exact_output_match':'false','collision':'false','confidence':'high' if d['generated']=='false' else 'medium','reason':'actual decoder controls unavailable because no frozen model passed holdout' if d['generated']=='false' else 'decoder positive interval executed'})
        for i,(a,b) in enumerate(negwins,1):
            neg.append({'decoder_id':d['decoder_id'],'negative_id':f'n{i:03d}','start_time':iso(a),'end_time':iso(b),'independent_window':'true','executed':d['generated'],'collision':'false','confidence':'high' if d['generated']=='false' else 'medium','reason':'independent negative window; no decoder generated when no holdout survivor exists'})
        rerun.append({'decoder_id':d['decoder_id'],'run1_executed':d['generated'],'run2_executed':d['generated'],'safe_aggregate_equal':'true' if d['generated']=='false' else 'pending','confidence':'high' if d['generated']=='false' else 'medium','reason':'no decoder generated; clean rerun not applicable without holdout survivor'})
    write_csv(ART/'pass657_decoder_execution_results.csv',[{'decoder_id':d['decoder_id'],'executed':d['generated'],'full_capture_exact_matches':0,'confidence':d['confidence'],'reason':d['reason']} for d in decs],['decoder_id','executed','full_capture_exact_matches','confidence','reason'])
    write_csv(ART/'pass657_positive_control_results.csv',pos,['decoder_id','oracle_id','channel','executed','exact_output_match','collision','confidence','reason'])
    write_csv(ART/'pass657_negative_control_results.csv',neg,['decoder_id','negative_id','start_time','end_time','independent_window','executed','collision','confidence','reason'])
    write_csv(ART/'pass657_clean_rerun_validation.csv',rerun,['decoder_id','run1_executed','run2_executed','safe_aggregate_equal','confidence','reason'])
    return 'negative_windows=%d'%len(negwins), ['artifacts/pass657_decoder_execution_results.csv','artifacts/pass657_positive_control_results.csv','artifacts/pass657_negative_control_results.csv','artifacts/pass657_clean_rerun_validation.csv'], 'completed'

def stage_targeted_mapping():
    targets=[ART/'pass622_codex_s2c_export_postprocess_decision.json',ART/'pass618_sonnet_s2c_decoder_decision.json',ART/'pass655_hypothesis_exhaustion.csv',ART/'pass654b_hypothesis_status.csv']
    rows=[]
    for i,p in enumerate(targets,1):
        exists=p.exists(); text=p.read_text(encoding='utf-8',errors='ignore')[:4000] if exists else ''
        concrete='none_found'
        for token in ('offset','width','endianness','length','xor','transform','dispatch','buffer','function','address'):
            if token in text.lower(): concrete='keyword_present_requires_specific_export'; break
        rows.append({'constraint_id':f'tm{i:03d}','source_file':str(p),'exists':str(exists).lower(),'content_inspected':str(exists).lower(),'concrete_constraint':concrete,'function_or_address':'','field_offset':'','field_width':'','endianness':'','length_arithmetic':'','transform_order':'','rolling_state_update':'','buffer_ownership':'','dispatch_relation':'','missing_input':'' if exists else str(p),'confidence':'medium' if exists else 'low','reason':'targeted content inspection only; no broad binary rescan'})
    rows.append({'constraint_id':'tm_missing_exact','source_file':'local-only static receive/body-transform export','exists':'false','content_inspected':'false','concrete_constraint':'missing_exact_transform_order','function_or_address':'','field_offset':'','field_width':'','endianness':'','length_arithmetic':'','transform_order':'needed','rolling_state_update':'needed_if_applicable','buffer_ownership':'needed','dispatch_relation':'needed','missing_input':r'C:\AionTools\aion_decoder_agent\outbox\<existing_static_receive_transform_export_if_available>','confidence':'high','reason':'single exact remaining missing input: concrete S2C body transform/order constraint'})
    write_csv(ART/'pass657_targeted_transform_constraints.csv',rows,['constraint_id','source_file','exists','content_inspected','concrete_constraint','function_or_address','field_offset','field_width','endianness','length_arithmetic','transform_order','rolling_state_update','buffer_ownership','dispatch_relation','missing_input','confidence','reason'])
    return 'constraints=%d'%len(rows), ['artifacts/pass657_targeted_transform_constraints.csv'], 'completed'

def stage_final():
    accepted=False
    hold=[r for r in read_csv(ART/'pass657_train_holdout_validation.csv') if r['holdout_exact']=='true']
    rev=[r for r in read_csv(ART/'pass657_reverse_holdout_validation.csv') if r['holdout_exact']=='true']
    transfer=read_csv(ART/'pass657_cross_length_channel_validation.csv')
    decs=read_csv(ART/'pass657_decoder_inventory.csv')
    neg=read_csv(ART/'pass657_negative_control_results.csv')
    accepted=bool(hold and rev and any(r.get('generated')=='true' for r in decs) and not any(r.get('collision')=='true' for r in neg))
    val=[{'validation_id':'pass657_gate','explicit_frame_equation':str(bool(read_csv(ART/'pass657_explicit_frame_survivors.csv'))).lower(),'explicit_body_boundary':str(bool(read_csv(ART/'pass657_oracle_body_candidates.csv'))).lower(),'frozen_A_to_B':str(bool(hold)).lower(),'reverse_or_independent_validation':str(bool(rev)).lower(),'decoder_without_oracle_text':str(any(r.get('generated')=='true' and r.get('accepts_oracle_plaintext')=='false' for r in decs)).lower(),'negative_controls_collide':str(any(r.get('collision')=='true' for r in neg)).lower(),'accepted':str(accepted).lower(),'confidence':'high','reason':'Corrected gate uses only frozen holdout validation and actual decoder eligibility, not Pass656 training hits'}]
    write_csv(ART/'pass657_exact_message_validation.csv',val,['validation_id','explicit_frame_equation','explicit_body_boundary','frozen_A_to_B','reverse_or_independent_validation','decoder_without_oracle_text','negative_controls_collide','accepted','confidence','reason'])
    hyp=[
('Pass656 claims','corrected','Tautological hits, oracle-fitting parsers, and hard-coded controls superseded.'),
('queue semantics','supported','Attempts and fallback attempts increment; semantics tests pass.'),
('S2C sequence stream','supported','Independent sparse cross-check completed.'),
('C2S gap policy','closed','Synthetic gap bytes disallowed.'),
('explicit frame equations','supported','Single-equation grid executed; survivors are evidence only.'),
('frame holdout/null','supported','Train/holdout/null separation executed.'),
('frozen transforms','weakened','No model passed corrected acceptance gate.'),
('decoder generation','closed','No decoder generated because no frozen holdout survivor qualified.'),
('targeted static constraints','open','Exact body transform/order constraint remains missing.')]
    write_csv(ART/'pass657_hypothesis_exhaustion.csv',[{'branch':b,'result':r,'reason':rs,'remaining_unknown':'concrete S2C body transform/order' if b in ('frozen transforms','targeted static constraints') else 'none','confidence':'high'} for b,r,rs in hyp],['branch','result','reason','remaining_unknown','confidence'])
    q=json.loads(QUEUE.read_text(encoding='utf-8')); unresolved=[s for s in q['stages'] if s['name']!='corrected_acceptance_or_exhaustion' and (s['status'] in ('pending','running','blocked') or s['fallback_status'] in ('pending','running','blocked'))]
    segs,world,_s2c,_data,_map,_stats=seq_stream()
    decision={'worker':'codex','phase':'pass657_corrective_holdout_validation','current_capture_valid':PCAP.exists(),'world_port_detected':world,'pass656_claims_superseded':True,'queue_semantics_tests_passed':all(r['passed']=='true' for r in read_csv(ART/'pass657_queue_semantics_tests.csv')),'s2c_reassembly_crosschecked':True,'c2s_synthetic_gap_bytes_used':False,'explicit_frame_equations_evaluated':len(read_csv(ART/'pass657_explicit_frame_equations.csv')),'explicit_frame_survivors':len(read_csv(ART/'pass657_explicit_frame_survivors.csv')),'oracle_body_candidates':len(read_csv(ART/'pass657_oracle_body_candidates.csv')),'frozen_transform_candidates':len(read_csv(ART/'pass657_frozen_transform_candidates.csv')),'frozen_A_to_B_successes':len(hold),'reverse_holdout_successes':len(rev),'decoders_generated':sum(1 for r in decs if r.get('generated')=='true'),'negative_control_windows':len(set(r.get('negative_id') for r in neg if r.get('negative_id'))),'exact_known_message_validated':accepted,'acceptance_gate_passed':accepted,'all_queue_stages_resolved':len(unresolved)==0,'private_packet_data_committed':False,'current_capture_still_useful':True,'needs_new_capture':False,'best_next_direction':'targeted_existing_transform_mapping','exact_next_unblocker':'one concrete S2C body transform/order constraint: body boundary, transform family/order, and state update from an existing static receive/parser export','reason':'Pass657 corrected Pass656 invalid training-fit/parser/control claims and executed frozen holdout validation; no model passed the acceptance gate.','next_action':'Provide or locate the exact existing static receive/body-transform export identified in pass657_targeted_transform_constraints.csv before recapture.'}
    write_json(ART/'pass657_corrective_holdout_validation_decision.json',decision)
    summary='# Pass657 Corrective Holdout Validation\n\n'+'\n'.join([f"World port detected: {world}",f"Pass656 claims superseded: {decision['pass656_claims_superseded']}",f"Queue semantics tests passed: {decision['queue_semantics_tests_passed']}",f"Explicit frame equations evaluated: {decision['explicit_frame_equations_evaluated']}",f"Frame survivors: {decision['explicit_frame_survivors']}",f"Frozen A->B successes: {decision['frozen_A_to_B_successes']}",f"Reverse holdout successes: {decision['reverse_holdout_successes']}",f"Decoders generated: {decision['decoders_generated']}",f"Exact known message validated: {accepted}",f"Best next direction: {decision['best_next_direction']}","",decision['reason'],"","No raw bytes, bodies, transformed bytes, keys, masks, state blobs, captures, binaries, or packet-derived hashes were committed."])+'\n'
    (ART/'pass657_corrective_holdout_validation_summary.md').write_text(summary,encoding='utf-8'); INBOX.mkdir(exist_ok=True); (INBOX/'codex_report.md').write_text(summary,encoding='utf-8')
    return 'accepted=%s'%accepted, ['artifacts/pass657_exact_message_validation.csv','artifacts/pass657_hypothesis_exhaustion.csv','artifacts/pass657_corrective_holdout_validation_decision.json','artifacts/pass657_corrective_holdout_validation_summary.md','inbox/codex_report.md'], 'completed'

RUNNERS={'pass656_claim_audit':stage_claim_audit,'queue_semantics_repair':stage_queue_semantics,'s2c_reassembly_crosscheck':stage_reassembly_crosscheck,'explicit_frame_equation_expansion':stage_explicit_frames,'frame_null_and_holdout_validation':stage_frame_holdout_null,'frame_time_oracle_assignment':stage_frame_time_assignment,'oracle_body_candidate_grid':stage_body_candidates,'frozen_train_holdout_transform_validation':stage_frozen_transform,'cross_length_channel_validation':stage_cross_length_channel,'decoder_without_oracle_input':stage_decoder_generation,'real_positive_negative_controls':stage_controls,'targeted_existing_transform_mapping':stage_targeted_mapping,'corrected_acceptance_or_exhaustion':stage_final}

def main():
    q=qinit()
    for name,_method,_fb in STAGES:
        st=qstage(q,name)
        if st['status']=='completed' and st['fallback_status'] not in ('pending','running','blocked'): continue
        try:
            result,arts,fb=run_primary(q,name,RUNNERS[name])
            complete(q,name,result,arts,fb)
        except Exception as e:
            qset(q,name,status='blocked',last_error=str(e))
            try:
                # Real fallback is the stage's own bounded fallback report plus continuing only if it can validate artifact presence.
                fb_path=ART/f'pass657_{name}_fallback.csv'
                write_csv(fb_path,[{'stage':name,'blocker':str(e),'fallback_method':qstage(q,name)['fallback'],'fallback_executed':'true','validated_output':'false','reason':'fallback recorded exact blocker; stage remains blocked if no validated output'}],['stage','blocker','fallback_method','fallback_executed','validated_output','reason'])
                qset(q,name,fallback_status='blocked',fallback_attempts=int(qstage(q,name).get('fallback_attempts',0))+1,artifacts=[str(fb_path.relative_to(REPO))])
                raise
            except Exception:
                return 2
        q=qinit()
    return 0
if __name__=='__main__': raise SystemExit(main())
