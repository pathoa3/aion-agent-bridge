#!/usr/bin/env python3
from common import *
def main():
    packets=parse_pcapng(PCAP); world=detect_world_port(packets); groups={}
    for p in packets:
        if p.payload_len<=0 or p.server_port_guess is None: continue
        k=flow_key(p); d=groups.setdefault(k,{"packets":0,"payload_bytes":0,"s2c_packets":0,"c2s_packets":0,"s2c_bytes":0,"c2s_bytes":0,"first":p.ts,"last":p.ts})
        d["packets"]+=1; d["payload_bytes"]+=p.payload_len; d["first"]=min(d["first"],p.ts); d["last"]=max(d["last"],p.ts)
        if p.direction_guess=="S2C": d["s2c_packets"]+=1; d["s2c_bytes"]+=p.payload_len
        elif p.direction_guess=="C2S": d["c2s_packets"]+=1; d["c2s_bytes"]+=p.payload_len
    rows=[]
    for (sip,sport,cip,cport),d in sorted(groups.items(), key=lambda kv:(kv[0][1],kv[0][3])):
        role="login" if sport==LOGIN_PORT else "auxiliary" if sport==AUX_PORT else "event_side" if sport==SIDE_PORT else "world" if sport==world else "candidate_world" if 7770<=sport<=7799 else "other"
        rows.append({"flow_id":f"{cip}:{cport}<->{sip}:{sport}","server_ip":sip,"server_port":sport,"client_ip":cip,"client_port":cport,"packets":d["packets"],"payload_bytes":d["payload_bytes"],"s2c_packets":d["s2c_packets"],"c2s_packets":d["c2s_packets"],"s2c_bytes":d["s2c_bytes"],"c2s_bytes":d["c2s_bytes"],"first_time":iso_time(d["first"]),"last_time":iso_time(d["last"]),"duration_sec":round(d["last"]-d["first"],3),"role":role,"confidence":"high" if role in ("world","event_side","login","auxiliary") else "medium","reason":"dynamic inventory from current PCAP; world selected by high-volume long-lived port in 7770-7799"})
    write_csv(ART/"pass654b_flow_inventory.csv", rows, ["flow_id","server_ip","server_port","client_ip","client_port","packets","payload_bytes","s2c_packets","c2s_packets","s2c_bytes","c2s_bytes","first_time","last_time","duration_sec","role","confidence","reason"])
    cons=[{"check_name":"pcap_exists","result":bools(PCAP.exists()),"value":str(PCAP),"confidence":"high","reason":"input path checked"},{"check_name":"known_log_exists","result":bools(LOG.exists()),"value":str(LOG),"confidence":"high","reason":"input path checked"},{"check_name":"world_port_detected","result":bools(world is not None),"value":world or "","confidence":"high" if world else "low","reason":"dynamic world flow selection"},{"check_name":"side_10242_present","result":bools(any(int(r['server_port'])==SIDE_PORT for r in rows)),"value":SIDE_PORT,"confidence":"high","reason":"flow inventory includes side/event port"},{"check_name":"oracle_current_rows","result":bools(len([o for o in merged_oracles() if o['current_capture']])>=17),"value":len([o for o in merged_oracles() if o['current_capture']]),"confidence":"high","reason":"merged prompt and known log references"}]
    write_csv(ART/"pass654b_capture_consistency.csv", cons, ["check_name","result","value","confidence","reason"])
    print({"flows":len(rows),"world":world})
if __name__=="__main__": main()
