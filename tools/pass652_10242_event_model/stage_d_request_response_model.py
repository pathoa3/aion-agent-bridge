#!/usr/bin/env python3
from __future__ import annotations
from pass652_common import *

def main():
    batch=read_csv(ART/"pass652_s2c_batch_model.csv"); rows=[]
    by_text=defaultdict(list)
    for i,r in enumerate(batch,1):
        total=int(r.get("next_s2c_bytes_3s") or 0); count=int(r.get("next_s2c_count_3s") or 0); cdelta=r.get("c2s_delta_ms",""); sdelta=0 if count else ""
        guess="chat_event_metadata" if r.get("c2s22_frame") and count else "heartbeat"
        rec={"pair_id":f"pair_{i:03d}","marker_index":r["marker_index"],"marker_text":r["marker_text"],"c2s22_frame":r["c2s22_frame"],"c2s22_delta_ms":cdelta,"s2c_burst_start_frame":"","s2c_burst_delta_ms":sdelta,"s2c_burst_packet_count":count,"s2c_burst_total_bytes":total,"pair_latency_ms":sdelta,"repeat_consistent":r.get("repeat_consistent","false"),"model_guess":guess,"confidence":"high" if guess=="chat_event_metadata" and abs(int(cdelta or 99999))<=4000 else "medium" if guess=="chat_event_metadata" else "low","reason":"C2S 22-byte trigger to S2C burst pairing from safe metadata"}
        by_text[rec["marker_text"]].append(str(total)); rows.append(rec)
    for r in rows:
        vals=by_text[r["marker_text"]]; r["repeat_consistent"]=str(len(vals)>=2 and len(set(vals))==1).lower()
    fields=["pair_id","marker_index","marker_text","c2s22_frame","c2s22_delta_ms","s2c_burst_start_frame","s2c_burst_delta_ms","s2c_burst_packet_count","s2c_burst_total_bytes","pair_latency_ms","repeat_consistent","model_guess","confidence","reason"]
    write_csv(ART/"pass652_request_response_pairs.csv", rows, fields); print({"pairs":len(rows)}); return 0
if __name__=="__main__": raise SystemExit(main())
