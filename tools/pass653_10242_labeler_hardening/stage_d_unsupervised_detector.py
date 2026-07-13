#!/usr/bin/env python3
from pass653_common import *

def main():
    packets=parse_pcapng(PCAP); markers=load_markers(); c22=c2s22(packets); ranges=marker_windows(markers,1)
    events=[]
    for p in c22:
        f=score_event_at(packets,p.ts,0.05)
        if f["score"]>=0.38:
            near=nearest([type("M",(),{"ts":m["ts"],"marker_index":m["marker_index"]}) for m in markers], p.ts) if markers else None
            nm=None; nd=""
            if near:
                nm=next((m for m in markers if m["marker_index"]==near.marker_index),None); nd=int(round((p.ts-nm["ts"])*1000)) if nm else ""
            events.append({"event_id":f"u{len(events)+1:03d}","predicted_event_time":iso_time(p.ts),"predicted_event_frame":p.frame,"source_direction":"C2S","score":f["score"],"confidence":f["confidence"],"near_known_marker_index":nm["marker_index"] if nm and abs(nd)<=4000 else "","near_known_marker_delta_ms":nd if nm and abs(nd)<=4000 else "","matched_known_marker":str(bool(nm and abs(nd)<=4000)).lower(),"reason":"unsupervised c2s22 candidate scored from timing, nearby s2c metadata, cadence break, and burst signatures"})
    write_csv(ART/"pass653_unsupervised_10242_events.csv", events, ["event_id","predicted_event_time","predicted_event_frame","source_direction","score","confidence","near_known_marker_index","near_known_marker_delta_ms","matched_known_marker","reason"])
    ev_ts=[parse_ts(e["predicted_event_time"]) for e in events]
    def matched(sec): return sum(1 for m in markers if any(t is not None and abs(t-m["ts"])<=sec for t in ev_ts))
    m1,m2,m4=matched(1),matched(2),matched(4)
    unmatched=len(markers)-m4; without=sum(1 for e in events if e["matched_known_marker"]!="true")
    precision=(len(events)-without)/len(events) if events else 0; recall=m4/len(markers) if markers else 0
    metrics=[("predicted_event_count",len(events),"medium","c2s22 candidates above threshold"),("known_markers_matched_within_1s",m1,"medium","unsupervised event near marker"),("known_markers_matched_within_2s",m2,"medium","unsupervised event near marker"),("known_markers_matched_within_4s",m4,"medium","unsupervised event near marker"),("unmatched_known_markers",unmatched,"medium","known markers not covered within 4s"),("predicted_events_without_known_marker",without,"medium","potential false positives or non-marker events"),("precision_hint",round(precision,3),"low","known log incomplete for all visible events"),("recall_hint",round(recall,3),"medium","against S2C_A marker rows")]
    write_csv(ART/"pass653_unsupervised_detector_metrics.csv", [{"metric_name":a,"value":b,"confidence":c,"reason":d} for a,b,c,d in metrics], ["metric_name","value","confidence","reason"])
    print({"unsupervised_events":len(events)})
if __name__=="__main__": main()
