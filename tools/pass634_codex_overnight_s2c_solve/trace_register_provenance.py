#!/usr/bin/env python3
"""Summarize Path B register provenance from exported text."""
import argparse, csv, re
from pathlib import Path
PATH_B_FUNCS=['11B45846','11B56999','11B59337','11B59832','11B59838','11B5625B']
REGS=['RDX','RSI','RBX','BL','RBP','RCX','RDI']

def write_csv(path, fields, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        w=csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for r in rows: w.writerow({k:r.get(k,'') for k in fields})

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--repo-root', default=r'C:\AionTools\aion-agent-bridge'); ap.add_argument('--export-dir', action='append', default=[]); ns=ap.parse_args()
    repo=Path(ns.repo_root); art=repo/'artifacts'; dirs=[Path(d) for d in (ns.export_dir or [r'C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports', r'C:\AionTools\aion_decoder_agent\outbox\pass631_path_b_xrefs'])]
    rows=[]
    for d in dirs:
        for p in d.glob('*.disasm.txt'):
            if not any(x in p.name.upper() for x in PATH_B_FUNCS): continue
            func='0x'+p.name[:8].upper(); text=p.read_text(encoding='utf-8', errors='replace')
            for reg in REGS:
                hits=[]
                for line in text.splitlines():
                    if re.search(r'\b'+re.escape(reg)+r'\b', line, re.I): hits.append(line.strip())
                status='unknown'; confidence='low'; summary='not observed in disasm export'
                if hits:
                    summary='; '.join(hits[:3])
                    status='observed_not_proven_source'; confidence='medium'
                    if reg=='RDX' and func=='0x11B59337':
                        status='RDX flows into final RBP/context base but caller source unknown'; confidence='medium'
                    if reg in ('RSI','BL','RBX') and func=='0x11B5625B':
                        status='dispatcher uses effective register state; entry source still unknown'; confidence='medium'
                rows.append({'register':reg,'path_b_stage':func,'source_function':func,'source_address':'','source_kind':status,'evidence_summary':summary,'confidence':confidence,'next_hop':'Need caller/wrapper export that reaches this stage with parameter/register setup'})
    # Add synthesized cross-function facts from prior Path B decompile review.
    rows.extend([
        {'register':'RDX','path_b_stage':'0x11B59337','source_function':'FUN_11b59337','source_address':'0x11B59337','source_kind':'parameter_to_context_base','evidence_summary':'pcode/disasm show FUN_11b59337 saves/copies incoming RDX before tail branch; caller that supplies RDX is not present in recv wrapper exports','confidence':'medium','next_hop':'Need non-entry caller or recv wrapper preserving RDX into FUN_11b59337'},
        {'register':'RSI','path_b_stage':'0x11B5625B','source_function':'FUN_11b5625b','source_address':'0x11B5625B','source_kind':'unknown_entry_state','evidence_summary':'dispatcher depends on incoming RSI/effective BL; exported predecessor paths A/C/D are rejected helper/init paths','confidence':'medium','next_hop':'Need concrete Path B receive predecessor with RSI setup'},
        {'register':'BL/RBX','path_b_stage':'0x11B5625B','source_function':'FUN_11b5625b','source_address':'0x11B5625B','source_kind':'unknown_effective_opcode_modifier','evidence_summary':'no exported receive-path predecessor seeds BL/RBX for Path B','confidence':'medium','next_hop':'Resolve RSI/RBX handoff from real caller before bounded VM trace'},
        {'register':'RBP+0','path_b_stage':'0x11B59337 -> 0x11B5625B','source_function':'FUN_11b59337','source_address':'','source_kind':'depends_on_unknown_RDX_context','evidence_summary':'[RBP+0] PC offset cannot be resolved because RBP base is the unresolved RDX context','confidence':'medium','next_hop':'Need context struct creation/write export for RDX object'},
    ])
    write_csv(art/'pass634_codex_register_provenance.csv', ['register','path_b_stage','source_function','source_address','source_kind','evidence_summary','confidence','next_hop'], rows)
    print({'register_rows':len(rows)})
if __name__=='__main__': main()
