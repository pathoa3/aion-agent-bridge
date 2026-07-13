#!/usr/bin/env python3
from pass655_common import *
def main():
    packets=parse_pcapng(PCAP); world=detect_world_port(packets); groups={}
    for p in packets:
        if p.payload_len<=0 or p.server_port_guess is None: continue
        k=flow_key(p); d=groups.setdefault(k,{"packets":0,"bytes":0,"s2c_packets":0,"c2s_packets":0,"s2c_bytes":0,"c2s_bytes":0,"first":p.ts,"last":p.ts})
        d["packets"]+=1; d["bytes"]+=p.payload_len; d["first"]=min(d["first"],p.ts); d["last"]=max(d["last"],p.ts)
        if p.direction_guess=="S2C": d["s2c_packets"]+=1; d["s2c_bytes"]+=p.payload_len
        elif p.direction_guess=="C2S": d["c2s_packets"]+=1; d["c2s_bytes"]+=p.payload_len
    rows=[]
    for (sip,sport,cip,cport),d in sorted(groups.items(), key=lambda kv:(kv[0][1],kv[0][3])):
        role="login" if sport==LOGIN_PORT else "auxiliary" if sport==AUX_PORT else "side_control" if sport==SIDE_PORT else "world" if sport==world else "candidate_world" if 7770<=sport<=7799 else "other"
        rows.append({"flow_id":f"{cip}:{cport}<->{sip}:{sport}","server_ip":sip,"server_port":sport,"client_ip":cip,"client_port":cport,"packets":d["packets"],"payload_bytes":d["bytes"],"s2c_packets":d["s2c_packets"],"c2s_packets":d["c2s_packets"],"s2c_bytes":d["s2c_bytes"],"c2s_bytes":d["c2s_bytes"],"first_time":iso_time(d["first"]),"last_time":iso_time(d["last"]),"duration_sec":round(d["last"]-d["first"],3),"role":role,"confidence":"high" if role in ("world","side_control","login","auxiliary") else "medium","reason":"fresh inventory from current PCAP; world dynamically selected"})
    safe_write_csv(ART/"pass655_flow_inventory.csv", rows, ["flow_id","server_ip","server_port","client_ip","client_port","packets","payload_bytes","s2c_packets","c2s_packets","s2c_bytes","c2s_bytes","first_time","last_time","duration_sec","role","confidence","reason"])
    first=min((p.ts for p in packets if p.ts), default=None); last=max((p.ts for p in packets if p.ts), default=None)
    ors=authoritative_oracles(); inside=sum(1 for o in ors if first is not None and last is not None and first<=o['ts_start']<=last and first<=o['ts_end']<=last)
    audit=[{"check_name":"pcap_exists","result":bools(PCAP.exists()),"value":str(PCAP),"confidence":"high","reason":"input file"},{"check_name":"capture_start","result":bools(first is not None),"value":iso_time(first),"confidence":"high","reason":"first parsed packet timestamp"},{"check_name":"capture_end","result":bools(last is not None),"value":iso_time(last),"confidence":"high","reason":"last parsed packet timestamp"},{"check_name":"world_flow_detected","result":bools(world is not None),"value":world or "","confidence":"high" if world else "low","reason":"dynamic high-volume world-range flow"},{"check_name":"side_10242_present","result":bools(any(int(r['server_port'])==SIDE_PORT for r in rows)),"value":SIDE_PORT,"confidence":"high","reason":"side/control flow inventory"},{"check_name":"all_oracle_intervals_inside_capture","result":bools(inside==17),"value":inside,"confidence":"high" if inside==17 else "low","reason":"authoritative chat.log seconds within PCAP span"}]
    safe_write_csv(ART/"pass655_capture_audit.csv", audit, ["check_name","result","value","confidence","reason"])
    print({"stage":"01","flows":len(rows),"world":world,"inside":inside})
if __name__=="__main__": main()
