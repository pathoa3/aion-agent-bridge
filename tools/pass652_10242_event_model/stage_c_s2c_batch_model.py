#!/usr/bin/env python3
from __future__ import annotations
from pass652_common import *

def main():
    packets=parse_pcapng(PCAP); markers=load_markers(); c2s22=[p for p in packets_10242(packets,"C2S") if p.payload_len==22]; s2c=packets_10242(packets,"S2C"); rows=[]
    by_text=defaultdict(list)
    tmp=[]
    for m in markers:
        n=nearest(c2s22,m["ts"]); anchor=n.ts if n else m["ts"]
        rec={"marker_index":m["marker_index"],"marker_text":m["marker_text"],"marker_len_ascii":m["marker_len_ascii"],"occurrence_index":m["occurrence_index"],"c2s22_frame":n.frame if n else "","c2s_delta_ms":delta_ms(n,m["ts"])}
        for sec in (1,3,5):
            cand=[p for p in s2c if anchor is not None and anchor<=p.ts<=anchor+sec]
            rec[f"next_s2c_count_{sec}s"]=len(cand); rec[f"next_s2c_bytes_{sec}s"]=sum(p.payload_len for p in cand)
        nexts=[p for p in s2c if anchor is not None and anchor<=p.ts<=anchor+5]
        rec["largest_next_s2c_len"]=max((p.payload_len for p in nexts), default=0)
        by_text[m["marker_text"]].append(str(rec["largest_next_s2c_len"])); tmp.append(rec)
    for rec in tmp:
        vals=by_text[rec["marker_text"]]; repeat=len(vals)>=2 and len(set(vals))==1
        rec.update({"repeat_consistent":str(repeat).lower(),"length_signal":"repeat_len_stable" if repeat else "weak_or_variable","confidence":"high" if repeat and rec["largest_next_s2c_len"] else "medium" if rec["largest_next_s2c_len"] else "low","reason":"S2C batch sizes after nearest C2S 22-byte trigger; lengths only"})
        rows.append(rec)
    fields=["marker_index","marker_text","marker_len_ascii","occurrence_index","c2s22_frame","c2s_delta_ms","next_s2c_count_1s","next_s2c_bytes_1s","next_s2c_count_3s","next_s2c_bytes_3s","next_s2c_count_5s","next_s2c_bytes_5s","largest_next_s2c_len","repeat_consistent","length_signal","confidence","reason"]
    write_csv(ART/"pass652_s2c_batch_model.csv", rows, fields)
    print({"batch_rows":len(rows)})
    return 0
if __name__=="__main__": raise SystemExit(main())
