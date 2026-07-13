#!/usr/bin/env python3
from pass653_common import *

def event_sources():
    rows=[]
    for m in load_markers(): rows.append({"event_id":f"m{m['marker_index']:03d}","marker_index":m["marker_index"],"marker_text":m["marker_text"],"ts":m["ts"]})
    for e in read_csv(ART/"pass653_unsupervised_10242_events.csv"):
        ts=parse_ts(e.get("predicted_event_time","")); rows.append({"event_id":e["event_id"],"marker_index":e.get("near_known_marker_index",""),"marker_text":"","ts":ts})
    return rows

def main():
    packets=parse_pcapng(PCAP); all10242=pkts(packets,CHAT_PORT); tmp=[]; key_to_cid={}; next_id=1
    for e in event_sources():
        lens,dirs,total,count=seq_sig(all10242,e["ts"],3,10)
        key=(lens,dirs)
        if key not in key_to_cid:
            key_to_cid[key]=f"c{next_id:03d}"; next_id+=1
        tmp.append((e,key_to_cid[key],lens,dirs,total,count))
    buckets=defaultdict(list); assigns=[]
    for e,cid,lens,dirs,total,count in tmp:
        assigns.append({"event_id":e["event_id"],"marker_index":e["marker_index"],"marker_text":e["marker_text"],"cluster_id":cid,"length_sequence_signature":lens,"direction_sequence_signature":dirs,"cluster_confidence":"medium" if count else "low","reason":"clustered by safe length and direction sequence signature"})
        buckets[cid].append((e,lens,dirs,total))
    clusters=[]
    for cid in sorted(buckets):
        vals=buckets[cid]; totals=[v[3] for v in vals]
        clusters.append({"cluster_id":cid,"event_count":len(vals),"known_marker_count":sum(1 for v in vals if str(v[0].get("event_id","")).startswith("m")),"typical_length_sequence":vals[0][1],"typical_direction_sequence":vals[0][2],"total_bytes_range":f"{min(totals)}-{max(totals)}" if totals else "","confidence":"medium" if len(vals)>=2 else "low","reason":"safe metadata cluster; no payload bytes or hashes"})
    write_csv(ART/"pass653_10242_s2c_batch_clusters.csv", clusters, ["cluster_id","event_count","known_marker_count","typical_length_sequence","typical_direction_sequence","total_bytes_range","confidence","reason"])
    write_csv(ART/"pass653_event_to_batch_cluster.csv", assigns, ["event_id","marker_index","marker_text","cluster_id","length_sequence_signature","direction_sequence_signature","cluster_confidence","reason"])
    print({"clusters":len(clusters),"assignments":len(assigns)})
if __name__=="__main__": main()
