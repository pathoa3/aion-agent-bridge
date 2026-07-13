#!/usr/bin/env python3
from __future__ import annotations
from pass651_common import *


def main() -> int:
    packets=parse_pcapng(PCAP); markers,_old,_total=load_current_markers(); rows=[]
    c2s22=[p for p in packets_for(packets,10242,"C2S") if p.payload_len==22 and p.ts is not None]
    s2c=[p for p in packets_for(packets,10242,"S2C") if p.ts is not None]
    repeat_vals=defaultdict(list)
    tmp=[]
    for m in markers:
        ts=m["ts"]
        nearest=min(c2s22,key=lambda p:abs(p.ts-ts)) if ts and c2s22 else None
        next_s=[p for p in s2c if ts and p.ts>=ts]
        nxt=next_s[0] if next_s else None
        rec={"marker_index":m["marker_index"],"marker_text":m["marker_text"],"nearest_c2s_22_frame":nearest.frame if nearest else "","c2s_delta_ms":int(round((nearest.ts-ts)*1000)) if nearest and ts else "","next_s2c_batch_frame":nxt.frame if nxt else "","next_s2c_delta_ms":int(round((nxt.ts-ts)*1000)) if nxt and ts else "","next_s2c_len":nxt.payload_len if nxt else ""}
        repeat_vals[m["marker_text"]].append(str(rec["next_s2c_len"]))
        tmp.append(rec)
    for rec in tmp:
        vals=[v for v in repeat_vals[rec["marker_text"]] if v]
        repeat = bool(len(vals)>=2 and len(set(vals))==1)
        cdelta=abs(int(rec["c2s_delta_ms"])) if rec["c2s_delta_ms"]!="" else 999999
        sdelta=abs(int(rec["next_s2c_delta_ms"])) if rec["next_s2c_delta_ms"]!="" else 999999
        supported = cdelta<=3000 and rec["nearest_c2s_22_frame"]!=""
        rec.update({"repeat_consistent":str(repeat).lower(),"length_signal":"repeat_len_stable" if repeat else "weak_or_variable","confidence":"high" if supported and repeat else "medium" if supported else "low","reason":"10242 C2S 22-byte timing and next S2C batch metadata only"})
        rows.append(rec)
    fields=["marker_index","marker_text","nearest_c2s_22_frame","c2s_delta_ms","next_s2c_batch_frame","next_s2c_delta_ms","next_s2c_len","repeat_consistent","length_signal","confidence","reason"]
    write_csv(ART/"pass651_10242_event_model.csv", rows, fields)
    print({"event_rows":len(rows)})
    return 0
if __name__ == "__main__": raise SystemExit(main())
