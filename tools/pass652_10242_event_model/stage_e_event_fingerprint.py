#!/usr/bin/env python3
from __future__ import annotations
from pass652_common import *

def bin_class(data):
    st=byte_class(data)
    return f"e{int(st['entropy'])}_z{int(st['zero']*10)}_p{int(st['printable']*10)}_u{int(st['utf16']*10)}"

def main():
    packets=parse_pcapng(PCAP); markers=load_markers(); rows=[]; by_text=defaultdict(list)
    for m in markers:
        selected=win_packets(packets,m,5); selected.sort(key=lambda p:(p.ts,p.frame))
        lens="-".join(("C" if p.direction_guess=="C2S" else "S")+str(p.payload_len) for p in selected[:12])
        dirs="".join("C" if p.direction_guess=="C2S" else "S" for p in selected[:20])
        times="-".join(signature_bucket_delta(delta_ms(p,m["ts"])) for p in selected[:8])
        bc="-".join(bin_class(p.payload) for p in selected[:6])
        rec={"event_fingerprint_id":f"fp_{m['marker_index']:03d}","marker_text":m["marker_text"],"occurrence_index":m["occurrence_index"],"server_port":10242,"window_sec":5,"length_sequence_signature":lens,"direction_sequence_signature":dirs,"timing_bucket_signature":times,"byte_class_signature":bc,"repeat_fingerprint_match":"pending","confidence":"medium","reason":"safe metadata fingerprint: lengths, directions, timing buckets, byte-class bins only"}
        by_text[m["marker_text"]].append(lens+"|"+dirs+"|"+times); rows.append(rec)
    for r in rows:
        vals=by_text[r["marker_text"]]; r["repeat_fingerprint_match"]=str(len(vals)>=2 and len(set(vals))==1).lower(); r["confidence"]="high" if r["repeat_fingerprint_match"]=="true" else "medium"
    fields=["event_fingerprint_id","marker_text","occurrence_index","server_port","window_sec","length_sequence_signature","direction_sequence_signature","timing_bucket_signature","byte_class_signature","repeat_fingerprint_match","confidence","reason"]
    write_csv(ART/"pass652_event_fingerprints.csv", rows, fields); print({"fingerprints":len(rows)}); return 0
if __name__=="__main__": raise SystemExit(main())
