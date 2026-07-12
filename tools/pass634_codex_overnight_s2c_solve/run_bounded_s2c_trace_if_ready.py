#!/usr/bin/env python3
"""Gate bounded S2C VM trace execution on concrete static tuple availability."""
import argparse, csv, json
from pathlib import Path

def read_csv(path):
    if not path.exists(): return []
    with path.open('r', newline='', encoding='utf-8', errors='replace') as f:
        return list(csv.DictReader(f))

def write_csv(path, fields, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        w=csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for r in rows: w.writerow({k:r.get(k,'') for k in fields})

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--repo-root', default=r'C:\AionTools\aion-agent-bridge'); ns=ap.parse_args(); repo=Path(ns.repo_root); art=repo/'artifacts'
    prov=read_csv(art/'pass634_codex_register_provenance.csv')
    concrete_kinds = {'concrete', 'known_constant', 'known_parameter', 'known_context', 'known_tuple'}
    rsi=any(r['register']=='RSI' and r['source_kind'].lower() in concrete_kinds for r in prov)
    pc=any(r['register']=='RBP+0' and r['source_kind'].lower() in concrete_kinds for r in prov)
    bl=any(r['register'] in ('BL','BL/RBX') and r['source_kind'].lower() in concrete_kinds for r in prov)
    ready=rsi and pc and bl
    rows=[{'trace_id':'PASS634-S2C-TRACE-001','bounded_vm_trace_run':str(ready).lower(),'valid_trace_candidate':'false','rsi_base_known':str(rsi).lower(),'pc_offset_known':str(pc).lower(),'effective_bl_known':str(bl).lower(),'blocker':'' if ready else 'RSI base, [RBP+0] PC offset, and effective BL are not concrete in current static exports','next_step':'run Pass627 with concrete tuple' if ready else 'obtain targeted recv-wrapper/code-xref export that reaches Path B and shows register setup'}]
    write_csv(art/'pass634_codex_bounded_trace_validation.csv', ['trace_id','bounded_vm_trace_run','valid_trace_candidate','rsi_base_known','pc_offset_known','effective_bl_known','blocker','next_step'], rows)
    print(json.dumps({'ready':ready}))
if __name__=='__main__': main()
