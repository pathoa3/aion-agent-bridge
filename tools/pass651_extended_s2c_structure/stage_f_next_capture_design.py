#!/usr/bin/env python3
from __future__ import annotations
from pass651_common import *


def avg(vals): return sum(vals)/len(vals) if vals else 0.0

def classify(ent, utf16, zero, printable):
    if utf16>0.35 and zero>0.2: return "utf16_like"
    if printable>0.65: return "ascii_or_text_like"
    if ent>6.5: return "compressed_or_encrypted"
    return "structured_binary"

def main() -> int:
    packets=parse_pcapng(PCAP); markers,_old,_total=load_current_markers(); LOCAL_OUT.mkdir(parents=True, exist_ok=True)
    local_rows=[]; summary=[]
    for port,direction in ((7780,"S2C"),(10242,"S2C"),(10242,"C2S")):
        stats=[]
        for m in markers:
            data=b"".join(p.payload for p in local_window_packets(packets,m,port,direction,10))
            st=byte_stats(data); stats.append(st)
            local_rows.append({"flow_role":flow_role(port),"server_port":port,"direction":direction,"marker_index":m["marker_index"],"payload_bytes":len(data),"entropy_hint":f"{st['entropy']:.3f}","utf16_likeness_hint":f"{st['utf16_likeness']:.3f}","zero_byte_ratio_hint":f"{st['zero_ratio']:.3f}","printable_ratio_hint":f"{st['printable_ratio']:.3f}"})
        ent=avg([s["entropy"] for s in stats]); utf=avg([s["utf16_likeness"] for s in stats]); zero=avg([s["zero_ratio"] for s in stats]); pr=avg([s["printable_ratio"] for s in stats]); likely=classify(ent,utf,zero,pr)
        summary.append({"flow_role":flow_role(port),"server_port":port,"window_type":f"{direction}_pm10s_concat","rows_tested":len(stats),"avg_entropy_hint":f"{ent:.3f}","utf16_likeness_hint":f"{utf:.3f}","zero_byte_ratio_hint":f"{zero:.3f}","printable_ratio_hint":f"{pr:.3f}","likely_encoding":likely,"confidence":"medium","reason":"aggregate local-only payload triage; no raw bytes or hashes written"})
    with (LOCAL_OUT/"local_payload_triage_notes.txt").open("w",encoding="utf-8") as f:
        f.write("Pass651 local-only payload triage. Contains aggregate byte-class hints only, no raw payload bytes and no packet hashes.\n")
    write_csv(LOCAL_OUT/"local_window_payload_stats.csv", local_rows, ["flow_role","server_port","direction","marker_index","payload_bytes","entropy_hint","utf16_likeness_hint","zero_byte_ratio_hint","printable_ratio_hint"])
    write_csv(ART/"pass651_local_payload_triage_summary.csv", summary, ["flow_role","server_port","window_type","rows_tested","avg_entropy_hint","utf16_likeness_hint","zero_byte_ratio_hint","printable_ratio_hint","likely_encoding","confidence","reason"])
    print({"triage_rows":len(summary),"local_out":str(LOCAL_OUT)})
    return 0
if __name__ == "__main__": raise SystemExit(main())
