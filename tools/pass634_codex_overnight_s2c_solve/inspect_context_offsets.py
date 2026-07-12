#!/usr/bin/env python3
"""Scan exported static text for context-like base+offset accesses."""
import argparse, csv, re
from pathlib import Path
BASES=['RDX','RBP','RSI','RDI','RCX','RBX']
PATTERNS=[
    re.compile(r'(?P<op>MOV|LEA|CMP|ADD|SUB|XOR|AND|OR)\s+[^\n]*\[(?P<base>RDX|RBP|RSI|RDI|RCX|RBX)(?P<off>[+\-]0x[0-9A-Fa-f]+|[+\-]\d+)?\]', re.I),
    re.compile(r'(?P<op>LOAD|STORE).*\(register,\s*(?P<reg>0x[0-9a-f]+),', re.I),
]
REG_BASE={'0x10':'RDX','0x28':'RBP','0x30':'RSI','0x38':'RDI','0x8':'RCX','0x18':'RBX'}

def write_csv(path, fields, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        w=csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for r in rows: w.writerow({k:r.get(k,'') for k in fields})

def fn(p): return '0x'+p.name[:8].upper() if re.match(r'[0-9A-Fa-f]{8}_', p.name) else ''

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--repo-root', default=r'C:\AionTools\aion-agent-bridge'); ap.add_argument('--export-dir', action='append', default=[]); ns=ap.parse_args()
    dirs=[Path(d) for d in (ns.export_dir or [r'C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports', r'C:\AionTools\aion_decoder_agent\outbox\pass631_path_b_xrefs'])]
    rows=[]; seen=set()
    for d in dirs:
        for p in list(d.glob('*.disasm.txt'))+list(d.glob('*.pcode.txt'))+list(d.glob('*.decomp.txt')):
            text=p.read_text(encoding='utf-8', errors='replace')
            for i,line in enumerate(text.splitlines(),1):
                m=PATTERNS[0].search(line)
                if m:
                    base=m.group('base').upper(); off=m.group('off') or '+0'; op=m.group('op').upper(); rw='read_or_write'
                    if re.search(r'\[.*\]\s*,', line): rw='read_from_base_offset'
                    elif re.search(r',\s*\[.*\]', line): rw='read_from_base_offset'
                    k=(p.name,i,base,off,line.strip())
                    if k not in seen:
                        seen.add(k); rows.append({'offset':off,'base_register':base,'function':fn(p),'source_file':p.name,'line_number':i,'access':'disasm_'+rw,'source_value_or_target':'not_resolved','possible_role':'context/pc candidate' if base in ('RDX','RBP') else 'register scratch/helper','confidence':'low' if base not in ('RDX','RBP') else 'medium','notes':'address/label summary only'})
                if 'LOAD' in line or 'STORE' in line:
                    m=PATTERNS[1].search(line)
                    base='unknown'; off='unknown'
                    if m: base=REG_BASE.get(m.group('reg').lower(), m.group('reg'))
                    if base in ('RDX','RBP','RSI','RDI','RCX','RBX'):
                        k=(p.name,i,line.strip())
                        if k not in seen:
                            seen.add(k); rows.append({'offset':off,'base_register':base,'function':fn(p),'source_file':p.name,'line_number':i,'access':'pcode_'+('write' if 'STORE' in line else 'read'),'source_value_or_target':'not_resolved','possible_role':'context/pc candidate' if base in ('RDX','RBP') else 'register scratch/helper','confidence':'low','notes':'pcode register-space access; exact struct offset not recoverable from current summary'})
    write_csv(Path(ns.repo_root)/'artifacts'/'pass634_codex_context_offsets.csv', ['offset','base_register','function','source_file','line_number','access','source_value_or_target','possible_role','confidence','notes'], rows)
    print({'context_rows':len(rows)})
if __name__=='__main__': main()
