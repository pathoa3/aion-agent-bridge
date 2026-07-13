#!/usr/bin/env python3
from pass653_common import *

def sample_times(packets, markers):
    c22=c2s22(packets); times=[]; ranges=marker_windows(markers,5)
    mts=sorted(m["ts"] for m in markers if m.get("ts") is not None)
    if not mts: return []
    start,end=min(p.ts for p in pkts(packets,CHAT_PORT)),max(p.ts for p in pkts(packets,CHAT_PORT))
    for i,t in enumerate([start+5,start+15,max(start+1,mts[0]-12),min(end-1,mts[-1]+12),end-15,end-5]):
        if t and not in_any(t,ranges): times.append((f"baseline_{i+1}","before_after_or_edge",t))
    for i in range(len(mts)-1):
        mid=(mts[i]+mts[i+1])/2
        if not in_any(mid,ranges): times.append((f"between_{i+1}","between_marker_windows",mid))
    for p in c22:
        if not in_any(p.ts, marker_windows(markers,8)):
            times.append((f"ordinary_{len(times)+1}","ordinary_10242_c2s22",p.ts));
            if len([x for x in times if x[1]=="ordinary_10242_c2s22"])>=8: break
    return times[:24]

def main():
    packets=parse_pcapng(PCAP); markers=load_markers(); c22=c2s22(packets); s2c=s2c_chat(packets)
    rows=[]
    for sid,stype,ts in sample_times(packets,markers):
        n22=nearest(c22,ts); ns2c=nearest(s2c,ts); feat=score_event_at(packets,ts,0)
        risk="high" if feat["score"]>=0.65 else "medium" if feat["score"]>=0.4 else "low"
        rows.append({"sample_id":sid,"sample_type":stype,"sample_time":iso_time(ts),"nearest_c2s22_frame":n22.frame if n22 else "","c2s_delta_ms":delta_ms(n22,ts),"nearest_s2c_frame":ns2c.frame if ns2c else "","s2c_delta_ms":delta_ms(ns2c,ts),"metadata_label_score":feat["score"],"would_be_labeled_event":str(feat["score"]>=0.55).lower(),"false_positive_risk":risk,"confidence":feat["confidence"],"reason":"non-marker timestamp scored with same metadata features"})
    write_csv(ART/"pass653_false_positive_baseline.csv", rows, ["sample_id","sample_type","sample_time","nearest_c2s22_frame","c2s_delta_ms","nearest_s2c_frame","s2c_delta_ms","metadata_label_score","would_be_labeled_event","false_positive_risk","confidence","reason"])
    comp=[]
    marker_scores=[]
    for m in markers:
        f=score_event_at(packets,m["ts"],0); marker_scores.append({"delta":f["d22"],"score":f["score"],"event":True})
    base_scores=[{"delta":abs(int(r["c2s_delta_ms"])) if r["c2s_delta_ms"]!="" else None,"score":float(r["metadata_label_score"]),"event":r["would_be_labeled_event"]=="true"} for r in rows]
    for name,vals in [("known_markers",marker_scores),("baseline_non_markers",base_scores)]:
        deltas=[v["delta"] for v in vals if v["delta"] is not None]; scores=[v["score"] for v in vals]
        fp=sum(1 for v in vals if v["event"])/len(vals) if vals else 0
        comp.append({"class_name":name,"samples":len(vals),"median_abs_c2s22_delta_ms":median(deltas),"within_1s_count":sum(1 for d in deltas if d<=1000),"within_2s_count":sum(1 for d in deltas if d<=2000),"within_4s_count":sum(1 for d in deltas if d<=4000),"mean_label_score":mean(scores),"false_positive_rate_estimate":round(fp,3) if name.startswith("baseline") else "","confidence":confidence_from_count(len(vals)),"reason":"marker versus non-marker metadata timing baseline"})
    write_csv(ART/"pass653_marker_vs_baseline_score.csv", comp, ["class_name","samples","median_abs_c2s22_delta_ms","within_1s_count","within_2s_count","within_4s_count","mean_label_score","false_positive_rate_estimate","confidence","reason"])
    print({"baseline_rows":len(rows)})
if __name__=="__main__": main()
