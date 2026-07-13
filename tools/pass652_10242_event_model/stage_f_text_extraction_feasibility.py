#!/usr/bin/env python3
from __future__ import annotations
from pass652_common import *

def transforms(text):
    yield "ascii_exact", text.encode("ascii",errors="ignore")
    yield "utf16le_exact", text.encode("utf-16le")
    yield "utf16be_exact", text.encode("utf-16be")
    yield "nul_split_ascii", b"\x00".join(bytes([c]) for c in text.encode("ascii",errors="ignore"))
    yield "visible_prefix_utf16le", ("::Spirips Whispers: "+text).encode("utf-16le")
    yield "lowercase_ascii", text.lower().encode("ascii",errors="ignore")
    yield "uppercase_ascii", text.upper().encode("ascii",errors="ignore")
    yield "no_underscore_ascii", text.replace("_","").encode("ascii",errors="ignore")
    parts=text.split("_")
    if len(parts)>=3: yield "numeric_id_ascii", parts[2].encode("ascii",errors="ignore")
    xrun="X"*(text.count("X")); yield "x_run_ascii", xrun.encode("ascii",errors="ignore")

def main():
    packets=parse_pcapng(PCAP); markers=load_markers(); rows=[]
    for direction in ("S2C","C2S"):
        for name in ["ascii_exact","utf16le_exact","utf16be_exact","nul_split_ascii","visible_prefix_utf16le","lowercase_ascii","uppercase_ascii","no_underscore_ascii","numeric_id_ascii","x_run_ascii"]:
            hits=0; tested=0; by_text=defaultdict(int)
            for m in markers:
                data=b"".join(p.payload for p in [p for p in win_packets(packets,m,15) if p.direction_guess==direction])
                for tname,needle in transforms(m["marker_text"]):
                    if tname!=name or not needle: continue
                    tested+=1
                    if data.find(needle)>=0:
                        hits+=1; by_text[m["marker_text"]]+=1
            comparable=[v>=2 for v in by_text.values()]
            rows.append({"flow_role":"chat_sidechannel_candidate","server_port":10242,"stream_direction":direction,"test_name":name,"rows_tested":tested,"hits":hits,"repeat_consistent":str(bool(comparable) and all(comparable)).lower(),"exact_marker_recovered":str(hits>0 and name in ("ascii_exact","utf16le_exact","utf16be_exact")).lower(),"confidence":"high" if hits else "low","reason":"local-only transform search; no matched bytes or blobs written"})
    fields=["flow_role","server_port","stream_direction","test_name","rows_tested","hits","repeat_consistent","exact_marker_recovered","confidence","reason"]
    write_csv(ART/"pass652_text_feasibility.csv", rows, fields); print({"feasibility_rows":len(rows)}); return 0
if __name__=="__main__": raise SystemExit(main())



