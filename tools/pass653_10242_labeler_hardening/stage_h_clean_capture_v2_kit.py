#!/usr/bin/env python3
from pass653_common import *

def marker_variant_needles(text):
    parts=text.split("_"); idx=parts[2] if len(parts)>2 else ""
    return [("utf16_marker_index", idx.encode("utf-16le")), ("ascii_marker_index", idx.encode("ascii",errors="ignore")), ("utf16_marker_len", str(len(text)).encode("utf-16le")), ("ascii_marker_len", str(len(text)).encode("ascii"))]

def main():
    packets=parse_pcapng(PCAP); markers=load_markers(); c22=c2s22(packets); rows=[]
    aligned=[]
    for m in markers:
        p=nearest(c22,m["ts"])
        if p: aligned.append((m,p))
    # Local-only byte inspection; output only booleans/counts/classes, never values.
    classes_by_repeat=defaultdict(list); classes_by_len=defaultdict(list); classes_by_idx=defaultdict(list)
    for m,p in aligned:
        cls=byte_class_name(p.payload)
        classes_by_repeat[m["marker_text"]].append(cls); classes_by_len[m["marker_len_ascii"]].append(cls); classes_by_idx[m["marker_text"].split("_")[2]].append(cls)
    repeat_cons=all(len(set(v))==1 for v in classes_by_repeat.values() if len(v)>=2)
    len_signal=len({k:tuple(v) for k,v in classes_by_len.items()})>1
    idx_signal=len({k:tuple(v) for k,v in classes_by_idx.items()})>1
    rows.append({"test_name":"byte_class_pattern","rows_tested":len(aligned),"hit_count":len(aligned),"marker_index_signal":str(idx_signal).lower(),"length_signal":str(len_signal).lower(),"repeat_consistency":str(repeat_cons).lower(),"exact_text_recovered":"false","confidence":"medium","reason":"compares zero/printable/high-byte class summaries for nearest 22-byte C2S packets only"})
    for tname in ["utf16_marker_index","ascii_marker_index","utf16_marker_len","ascii_marker_len"]:
        hits=0
        for m,p in aligned:
            needles=dict(marker_variant_needles(m["marker_text"]))
            needle=needles[tname]
            if needle and p.payload.find(needle)>=0: hits+=1
        rows.append({"test_name":tname,"rows_tested":len(aligned),"hit_count":hits,"marker_index_signal":str(hits>0 and "index" in tname).lower(),"length_signal":str(hits>0 and "len" in tname).lower(),"repeat_consistency":str(hits in (0,len(aligned))).lower(),"exact_text_recovered":"false","confidence":"low" if hits==0 else "medium","reason":"local-only transform search over aligned 22-byte packets; no bytes written"})
    write_csv(ART/"pass653_c2s22_transform_feasibility.csv", rows, ["test_name","rows_tested","hit_count","marker_index_signal","length_signal","repeat_consistency","exact_text_recovered","confidence","reason"])
    print({"transform_rows":len(rows)})
if __name__=="__main__": main()
