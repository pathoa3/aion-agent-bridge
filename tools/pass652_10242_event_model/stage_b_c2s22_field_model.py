#!/usr/bin/env python3
from __future__ import annotations
from pass652_common import *

def pattern_class(payload: bytes) -> str:
    # Safe class: zero/nonzero mask and variability class only, no values.
    return "Z".join([]) or f"z{payload.count(0)}_nz{len(payload)-payload.count(0)}"

def main():
    packets=parse_pcapng(PCAP); markers=load_markers(); c2s22=[p for p in packets_10242(packets,"C2S") if p.payload_len==22]
    near=[]; align=[]
    for m in markers:
        n=nearest(c2s22,m["ts"]); prevs=[p for p in c2s22 if n and p.ts<n.ts]; nexts=[p for p in c2s22 if n and p.ts>n.ts]
        prev=prevs[-1] if prevs else None; nxt=nexts[0] if nexts else None
        if n: near.append((m,n))
        align.append({"marker_index":m["marker_index"],"marker_text":m["marker_text"],"occurrence_index":m["occurrence_index"],"nearest_c2s22_frame":n.frame if n else "","c2s_delta_ms":delta_ms(n,m["ts"]),"prev_c2s22_delta_ms":delta_ms(prev,m["ts"]),"next_c2s22_delta_ms":delta_ms(nxt,m["ts"]),"c2s22_pattern_class":pattern_class(n.payload) if n else "none","repeat_pattern_consistent":"pending","confidence":"medium" if n and abs(int(delta_ms(n,m["ts"])))<=4000 else "low","reason":"nearest 22-byte C2S timing and byte-class pattern only"})
    by_text=defaultdict(set)
    for r in align: by_text[r["marker_text"]].add(r["c2s22_pattern_class"])
    for r in align: r["repeat_pattern_consistent"]=str(len(by_text[r["marker_text"]])==1).lower()
    write_csv(ART/"pass652_c2s22_marker_alignment.csv", align, ["marker_index","marker_text","occurrence_index","nearest_c2s22_frame","c2s_delta_ms","prev_c2s22_delta_ms","next_c2s22_delta_ms","c2s22_pattern_class","repeat_pattern_consistent","confidence","reason"])
    payloads=[p.payload for _m,p in near]
    rows=[]
    if payloads:
        length=len(payloads[0]); zero_positions=set(i for i in range(length) if all(p[i]==0 for p in payloads)); variable_positions=set(i for i in range(length) if len(set(p[i] for p in payloads))>1); const_positions=set(range(length))-variable_positions
        utf=sum(1 for p in payloads for i in range(1,len(p),2) if p[i]==0)/max(1,(len(payloads)*len(range(1,length,2))))
        rows.append({"field_model_id":"c2s22_near_marker_zero_variability","rows_tested":len(payloads),"byte_length":length,"zero_byte_positions_count":len(zero_positions),"variable_positions_count":len(variable_positions),"constant_positions_count":len(const_positions),"utf16_likeness":f"{utf:.3f}","repeat_consistency":str(repeat_consistency_by_text(align,"c2s22_pattern_class")).lower(),"marker_timing_alignment":"within_4s" if any(r["confidence"]=="medium" for r in align) else "weak","confidence":"high" if utf>0.8 else "medium","reason":"zero/nonzero and variability counts only; no byte values"})
    write_csv(ART/"pass652_c2s22_field_model.csv", rows, ["field_model_id","rows_tested","byte_length","zero_byte_positions_count","variable_positions_count","constant_positions_count","utf16_likeness","repeat_consistency","marker_timing_alignment","confidence","reason"])
    print({"c2s22_rows":len(align)})
    return 0
if __name__=="__main__": raise SystemExit(main())
