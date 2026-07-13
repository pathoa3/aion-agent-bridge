#!/usr/bin/env python3
from pass653_common import *

def baseline_penalty():
    rows=read_csv(ART/"pass653_false_positive_baseline.csv")
    if not rows: return 0.0
    rate=sum(1 for r in rows if r.get("would_be_labeled_event")=="true")/len(rows)
    return min(0.25, rate*0.25)

def main():
    packets=parse_pcapng(PCAP); markers=load_markers(); penalty=baseline_penalty(); rows=[]; deltas=[]
    for m in markers:
        f=score_event_at(packets,m["ts"],penalty); n=f["n22"]
        deltas.append(f["d22"])
        features=f"c2s22_delta;cadence_prev_next;s2c_1s={f['s2c1']};s2c_3s={f['s2c3']};s2c_5s={f['s2c5']};dir_seq={f['dirs']};len_seq_present={bool(f['lens'])}"
        rows.append({"marker_index":m["marker_index"],"marker_text":m["marker_text"],"expected_timestamp":m["logged_time"],"predicted_event_frame":n.frame if n else "","predicted_event_time":iso_time(n.ts) if n else "","delta_ms":delta_ms(n,m["ts"]),"score":f["score"],"confidence":f["confidence"],"false_positive_penalty":round(penalty,3),"features_used":features,"label_reason":"v2 score combines c2s22 timing, cadence, nearby s2c batch metadata, sequence signatures, and baseline penalty"})
    write_csv(ART/"pass653_event_labeler_v2_known_markers.csv", rows, ["marker_index","marker_text","expected_timestamp","predicted_event_frame","predicted_event_time","delta_ms","score","confidence","false_positive_penalty","features_used","label_reason"])
    high=sum(1 for r in rows if r["confidence"]=="high"); med=sum(1 for r in rows if r["confidence"]=="medium"); low=sum(1 for r in rows if r["confidence"]=="low")
    base=read_csv(ART/"pass653_false_positive_baseline.csv"); fpr=sum(1 for r in base if r.get("would_be_labeled_event")=="true")/len(base) if base else 1
    usable=(high+med>=6 and fpr<=0.5)
    metrics=[
      ("known_marker_count",len(rows),"high","S2C_A markers used"),("high_confidence_labels",high,"high","score>=0.75"),("medium_confidence_labels",med,"high","0.45<=score<0.75"),("low_confidence_labels",low,"high","score<0.45"),("median_abs_delta_ms",median(deltas),"high","nearest c2s22 delta"),("max_abs_delta_ms",max([d for d in deltas if d is not None] or [""]),"high","nearest c2s22 max abs delta"),("estimated_false_positive_rate",round(fpr,3),"medium","baseline non-marker label rate"),("usable_for_event_labeling_now",str(usable).lower(),"medium","requires >=6 medium/high labels and false positive rate <=0.5")]
    write_csv(ART/"pass653_event_labeler_v2_metrics.csv", [{"metric_name":a,"value":b,"confidence":c,"reason":d} for a,b,c,d in metrics], ["metric_name","value","confidence","reason"])
    print({"v2_rows":len(rows)})
if __name__=="__main__": main()

