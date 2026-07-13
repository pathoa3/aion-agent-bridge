#!/usr/bin/env python3
from pass655_common import *
def main():
    packets=parse_pcapng(PCAP); side=pkts(packets,SIDE_PORT); c2s=pkts(packets,SIDE_PORT,"C2S"); s2c=pkts(packets,SIDE_PORT,"S2C")
    intervals=[int(round((c2s[i].ts-c2s[i-1].ts)*1000)) for i in range(1,len(c2s))]
    med=median(intervals); jitter=median([abs(i-med) for i in intervals]) if med!="" else ""
    rows=[]
    near=sum(1 for p in c2s if any(abs(p.ts-o["ts_mid"])<=3 for o in authoritative_oracles()))
    role="heartbeat_control" if med!="" and jitter==0 else "event_metadata" if near>=8 else "mixed" if near else "unknown"
    rows.append({"role":role,"packets_tested":len(side),"c2s_packets":len(c2s),"s2c_packets":len(s2c),"median_c2s_interval_ms":med,"interval_jitter_ms":jitter,"near_oracle_c2s_packets":near,"content_transport_supported":"false","world_constraint_added":"timing aid only" if near else "none","confidence":"high" if role=="heartbeat_control" else "medium","reason":"10242 closed using corrected authoritative chat.log timestamps, cadence, and deterministic text-test negatives"})
    safe_write_csv(ART/"pass655_10242_role_decision.csv", rows, ["role","packets_tested","c2s_packets","s2c_packets","median_c2s_interval_ms","interval_jitter_ms","near_oracle_c2s_packets","content_transport_supported","world_constraint_added","confidence","reason"])
    print({"stage":"13","role":role})
if __name__=="__main__": main()
