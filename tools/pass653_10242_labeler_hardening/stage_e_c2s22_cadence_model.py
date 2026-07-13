#!/usr/bin/env python3
from pass653_common import *

def main():
    packets=parse_pcapng(PCAP); markers=load_markers(); c22=c2s22(packets)
    intervals=[int(round((c22[i].ts-c22[i-1].ts)*1000)) for i in range(1,len(c22))]
    marker_near=sum(1 for p in c22 if any(abs(p.ts-m["ts"])<=4 for m in markers))
    away=len(c22)-marker_near; near_rate=round(marker_near/max(1,len(c22)),3); away_rate=round(away/max(1,len(c22)),3)
    med=median(intervals); jitter=median([abs(i-med) for i in intervals]) if intervals and med!="" else ""
    heartbeat=round(max(0,1-(float(jitter if jitter!="" else 9999)/10000)),3) if intervals else 0
    event_score=round(near_rate,3); mixed=round((heartbeat+event_score)/2,3)
    model="mixed_heartbeat_event" if mixed>=0.45 and event_score>=0.2 else "heartbeat" if heartbeat>=0.65 else "event_trigger" if event_score>=0.45 else "poll"
    rows=[{"model_name":model,"packets_tested":len(c22),"median_interval_ms":med,"interval_jitter_ms":jitter,"near_marker_rate":near_rate,"away_from_marker_rate":away_rate,"heartbeat_score":heartbeat,"event_trigger_score":event_score,"mixed_model_score":mixed,"confidence":confidence_from_count(len(c22)),"reason":"22-byte C2S cadence compared to marker windows using timing only"}]
    write_csv(ART/"pass653_c2s22_cadence_model.csv", rows, ["model_name","packets_tested","median_interval_ms","interval_jitter_ms","near_marker_rate","away_from_marker_rate","heartbeat_score","event_trigger_score","mixed_model_score","confidence","reason"])
    detail=[]
    for m in markers:
        n=nearest(c22,m["ts"]); pi,ni=intervals_for(n,c22) if n else ("","")
        br=False
        if pi!="" and ni!="": br=abs(int(pi)-int(ni))>=2500
        likelihood="high" if abs_delta(n,m["ts"]) is not None and abs_delta(n,m["ts"])<=1000 else "medium" if abs_delta(n,m["ts"]) is not None and abs_delta(n,m["ts"])<=4000 else "low"
        detail.append({"marker_index":m["marker_index"],"marker_text":m["marker_text"],"nearest_c2s22_frame":n.frame if n else "","c2s_delta_ms":delta_ms(n,m["ts"]),"previous_interval_ms":pi,"next_interval_ms":ni,"cadence_break_near_marker":str(br).lower(),"event_trigger_likelihood":likelihood,"confidence":"medium","reason":"nearest C2S22 timing and adjacent interval comparison"})
    write_csv(ART/"pass653_c2s22_marker_alignment_detail.csv", detail, ["marker_index","marker_text","nearest_c2s22_frame","c2s_delta_ms","previous_interval_ms","next_interval_ms","cadence_break_near_marker","event_trigger_likelihood","confidence","reason"])
    print({"cadence_rows":len(rows),"detail":len(detail)})
if __name__=="__main__": main()

