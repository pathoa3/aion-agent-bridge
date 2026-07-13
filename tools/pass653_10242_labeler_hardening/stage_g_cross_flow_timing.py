#!/usr/bin/env python3
from pass653_common import *

def sources():
    rows=[]
    for m in load_markers(): rows.append({"event_id":f"m{m['marker_index']:03d}","marker_index":m["marker_index"],"ts":m["ts"],"frame":""})
    for e in read_csv(ART/"pass653_unsupervised_10242_events.csv"):
        rows.append({"event_id":e["event_id"],"marker_index":e.get("near_known_marker_index",""),"ts":parse_ts(e.get("predicted_event_time","")),"frame":e.get("predicted_event_frame","")})
    return rows

def main():
    packets=parse_pcapng(PCAP); s2c=world_s2c(packets); c2s=world_c2s(packets); rows=[]
    for e in sources():
        ns=nearest(s2c,e["ts"]); nc=nearest(c2s,e["ts"]); ds=abs_delta(ns,e["ts"]); dc=abs_delta(nc,e["ts"])
        burst=len(window(packets,WORLD_PORT,e["ts"],3,"S2C"))+len(window(packets,WORLD_PORT,e["ts"],3,"C2S"))
        adds=bool((ds is not None and ds<=1500) or (dc is not None and dc<=1500) or burst>=3)
        rows.append({"event_id":e["event_id"],"marker_index":e["marker_index"],"source_10242_frame":e["frame"],"event_time":iso_time(e["ts"]),"nearest_7780_s2c_frame":ns.frame if ns else "","delta_7780_s2c_ms":delta_ms(ns,e["ts"]),"nearest_7780_c2s_frame":nc.frame if nc else "","delta_7780_c2s_ms":delta_ms(nc,e["ts"]),"adds_confidence":str(adds).lower(),"confidence":"medium" if adds else "low","reason":f"nearest 7780 packets and +/-3s burst_count={burst}"})
    write_csv(ART/"pass653_cross_flow_timing.csv", rows, ["event_id","marker_index","source_10242_frame","event_time","nearest_7780_s2c_frame","delta_7780_s2c_ms","nearest_7780_c2s_frame","delta_7780_c2s_ms","adds_confidence","confidence","reason"])
    print({"cross_flow_rows":len(rows)})
if __name__=="__main__": main()
