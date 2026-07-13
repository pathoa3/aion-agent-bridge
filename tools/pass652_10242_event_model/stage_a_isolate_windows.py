#!/usr/bin/env python3
from __future__ import annotations
from pass652_common import *

def burst(delta,direction):
    d=int(delta)
    side="near" if abs(d)<=1000 else "pre" if d<0 else "post"
    return f"{side}_{direction.lower()}"

def main():
    packets=parse_pcapng(PCAP); markers=load_markers(); rows=[]
    for m in markers:
        for win in (5,15):
            selected=win_packets(packets,m,win); selected.sort(key=lambda p:(p.ts,p.frame))
            for i,p in enumerate(selected,1):
                d=delta_ms(p,m["ts"])
                rows.append({"marker_index":m["marker_index"],"marker_text":m["marker_text"],"marker_len_ascii":m["marker_len_ascii"],"occurrence_index":m["occurrence_index"],"window_sec":win,"packet_order":i,"frame":p.frame,"time_delta_ms":d,"direction":p.direction_guess,"tcp_len":p.payload_len,"is_22_byte_c2s":str(p.direction_guess=="C2S" and p.payload_len==22).lower(),"is_s2c_batch":str(p.direction_guess=="S2C" and p.payload_len>32).lower(),"burst_group":burst(d,p.direction_guess),"confidence":"high","reason":"10242 marker window safe metadata only"})
    fields=["marker_index","marker_text","marker_len_ascii","occurrence_index","window_sec","packet_order","frame","time_delta_ms","direction","tcp_len","is_22_byte_c2s","is_s2c_batch","burst_group","confidence","reason"]
    write_csv(ART/"pass652_stage_a_10242_windows.csv", rows, fields)
    print({"window_rows":len(rows)})
    return 0
if __name__=="__main__": raise SystemExit(main())
