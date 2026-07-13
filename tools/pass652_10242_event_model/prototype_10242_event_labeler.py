#!/usr/bin/env python3
from __future__ import annotations
from pass652_common import *

def main():
    packets=parse_pcapng(PCAP); markers=load_markers(); c2s22=[p for p in packets_10242(packets,"C2S") if p.payload_len==22]; rows=[]
    for m in markers:
        n=nearest(c2s22,m["ts"]); d=delta_ms(n,m["ts"])
        ad=abs(int(d)) if d!="" else 999999
        conf="high" if ad<=1000 else "medium" if ad<=4000 else "low"
        rows.append({"marker_index":m["marker_index"],"marker_text":m["marker_text"],"expected_timestamp":m["logged_time"],"predicted_event_frame":n.frame if n else "","predicted_event_time":iso_time(n.ts) if n else "","delta_ms":d,"source_flow":"10242","source_direction":"C2S","event_confidence":conf,"label_reason":"nearest 22-byte C2S packet to known visible marker timestamp; metadata label only"})
    fields=["marker_index","marker_text","expected_timestamp","predicted_event_frame","predicted_event_time","delta_ms","source_flow","source_direction","event_confidence","label_reason"]
    write_csv(ART/"pass652_prototype_event_labels.csv", rows, fields); print({"labels":len(rows)}); return 0
if __name__=="__main__": raise SystemExit(main())
