#!/usr/bin/env python3
"""Build Git-safe static callgraph/intersection artifacts for Pass634."""
import argparse, csv, re
from pathlib import Path

PATH_B = {"0x11B45846","0x11B52CE5","0x11B566DD","0x11B566B4","0x11B56999","0x11B56075","0x11B59337","0x11B59832","0x11B59838","0x11B5625B"}
REJECTED = {"0x11B5863D":"rejected_path_a_bsf_small_integer", "0x11B56F43":"rejected_path_c_helper_dispatch", "0x11B56C63":"rejected_path_d_startup_tls", "0x11B57075":"rejected_path_d_startup_tls"}
ADDR_RE = re.compile(r"0x[0-9A-Fa-f]{6,16}")

def norm(v):
    v=(v or '').strip()
    if v.lower().startswith('0x'):
        return '0x'+v[2:].upper()
    return v

def read_csv(p):
    if not p.exists(): return []
    with p.open('r', newline='', encoding='utf-8', errors='replace') as f:
        return list(csv.DictReader(f))

def write_csv(path, fields, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        w=csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for r in rows: w.writerow({k:r.get(k,'') for k in fields})

def fn_from_file(p):
    m=re.match(r'([0-9A-Fa-f]{8})_(.+)\.(?:pcode|disasm|decomp)\.txt$', p.name)
    if not m: return ('','')
    return ('0x'+m.group(1).upper(), m.group(2))

def collect(export_dirs):
    edges=[]; funcs={}; imports=[]
    for d in export_dirs:
        d=Path(d)
        for f in read_csv(d/'path_b_functions.csv') + read_csv(d/'candidate_functions.csv'):
            e=norm(f.get('entry') or f.get('function_entry') or f.get('address_requested'))
            n=f.get('name') or f.get('function') or f.get('label') or ''
            if e: funcs[e]=n
        for imp_name in ['path_b_import_refs.csv','import_refs.csv','recv_import_xrefs.csv']:
            for row in read_csv(d/imp_name):
                imports.append(row)

        for edge_name in ['path_b_call_edges.csv','call_edges.csv','recv_wrapper_edges.csv']:
            for r in read_csv(d/edge_name):
                fr=norm(r.get('from_entry')); to=norm(r.get('to_entry'))
                if fr and to:
                    edges.append({'from_entry':fr,'from_name':r.get('from_name',''),'to_entry':to,'to_name':r.get('to_name',''),'edge_type':r.get('edge_type') or 'csv_edge','source_file':str(d/edge_name)})
                    funcs.setdefault(fr, r.get('from_name','')); funcs.setdefault(to, r.get('to_name',''))

        # Tail-call / branch discovery from exported pcode/disasm.
        for p in list(d.glob('*.pcode.txt')) + list(d.glob('*.disasm.txt')):
            fr, fname = fn_from_file(p)
            if not fr: continue
            funcs.setdefault(fr, fname)
            text=p.read_text(encoding='utf-8', errors='replace')
            for line in text.splitlines():
                upper=line.upper()
                if 'BRANCH' not in upper and 'CALL' not in upper and 'JMP' not in upper:
                    continue
                addrs=[norm(a) for a in ADDR_RE.findall(line)]
                if len(addrs) >= 2:
                    to=addrs[-1]
                    if to != fr:
                        kind='tail_branch_or_call'
                        if 'BRANCHIND' in upper or 'CALLIND' in upper:
                            kind='indirect_branch_or_call'
                        edges.append({'from_entry':fr,'from_name':fname,'to_entry':to,'to_name':funcs.get(to,''),'edge_type':kind,'source_file':p.name})
    # dedupe
    seen=set(); out=[]
    for e in edges:
        k=(e['from_entry'],e['to_entry'],e['edge_type'],e['source_file'])
        if k in seen: continue
        seen.add(k); out.append(e)
    return funcs,out,imports

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--repo-root', default=r'C:\AionTools\aion-agent-bridge')
    ap.add_argument('--export-dir', action='append', default=[])
    ns=ap.parse_args()
    repo=Path(ns.repo_root); art=repo/'artifacts'
    dirs=ns.export_dir or [r'C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports', r'C:\AionTools\aion_decoder_agent\outbox\pass631_path_b_xrefs']
    funcs,edges,imports=collect(dirs)
    write_csv(art/'pass634_codex_callgraph_edges.csv', ['from_entry','from_name','to_entry','to_name','edge_type','source_file'], edges)

    preds=[]
    for e in edges:
        if e['to_entry'] in PATH_B or e['from_entry'] in PATH_B:
            role='path_b_internal' if e['from_entry'] in PATH_B and e['to_entry'] in PATH_B else ('predecessor_to_path_b' if e['to_entry'] in PATH_B else 'successor_from_path_b')
            useful='false'
            reason='Path B internal/helper edge only'
            if e['from_entry'] not in PATH_B and e['from_entry'] not in REJECTED and role=='predecessor_to_path_b':
                useful='possible'; reason='non-Path-B predecessor, but no recv/register evidence established'
            elif e['from_entry'] in REJECTED:
                reason=REJECTED[e['from_entry']]
            preds.append({**e, 'role':role, 'useful_for_s2c':useful, 'reason':reason})
    write_csv(art/'pass634_codex_path_b_predecessors.csv', ['from_entry','from_name','to_entry','to_name','edge_type','source_file','role','useful_for_s2c','reason'], preds)

    wrappers=[]
    for r in imports:
        api=r.get('api','')
        wrappers.append({'api':api,'import_address':r.get('import_address') or r.get('from_address') or '', 'caller_entry':norm(r.get('caller_entry','')), 'caller_name':r.get('caller_name',''), 'ref_type':r.get('ref_type',''), 'path_b_intersection':'false' if not norm(r.get('caller_entry','')) in PATH_B else 'true', 'notes':'blank caller means import thunk/symbol row only' if not r.get('caller_entry') else 'caller exported'})
    write_csv(art/'pass634_codex_exported_recv_wrappers.csv', ['api','import_address','caller_entry','caller_name','ref_type','path_b_intersection','notes'], wrappers)
    print({'edges':len(edges),'predecessors':len(preds),'wrappers':len(wrappers)})
if __name__=='__main__': main()
