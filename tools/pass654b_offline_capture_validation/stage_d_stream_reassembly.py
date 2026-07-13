#!/usr/bin/env python3
from common import *
def main():
    packets=parse_pcapng(PCAP); world=detect_world_port(packets); index_rows=[]
    for port,role in [(world,"world"),(SIDE_PORT,"event_side")]:
        if port is None: continue
        for direction in ("S2C","C2S"):
            total=0
            for p,s,e in stream_indices(packets,port,direction):
                index_rows.append({"flow_role":role,"server_port":port,"direction":direction,"frame":p.frame,"time":iso_time(p.ts),"tcp_len":p.payload_len,"stream_offset_start":s,"stream_offset_end":e,"confidence":"high","reason":"TCP payload stream order metadata only"}); total=e
    write_csv(ART/"pass654b_stream_index.csv", index_rows, ["flow_role","server_port","direction","frame","time","tcp_len","stream_offset_start","stream_offset_end","confidence","reason"])
    win_rows=[]; secs=[0,1,3,5,10]
    for o in [x for x in merged_oracles() if x["current_capture"]]:
        for port,role in [(world,"world"),(SIDE_PORT,"event_side")]:
            if port is None: continue
            for direction in ("S2C","C2S"):
                idx=stream_indices(packets,port,direction)
                for sec in secs:
                    ps=[p for p in pkts(packets,port,direction) if (nearest(pkts(packets,port,direction),o["ts"])==p if sec==0 else abs(p.ts-o["ts"])<=sec)]
                    offs=[(s,e) for p,s,e in idx if p in ps]
                    win_rows.append({"oracle_id":o["oracle_id"],"channel":o["channel"],"flow_role":role,"server_port":port,"direction":direction,"window_sec":"nearest" if sec==0 else sec,"first_frame":min([p.frame for p in ps], default=""),"last_frame":max([p.frame for p in ps], default=""),"packet_count":len(ps),"total_bytes":sum(p.payload_len for p in ps),"stream_offset_start":min([s for s,e in offs], default=""),"stream_offset_end":max([e for s,e in offs], default=""),"largest_packet_len":max([p.payload_len for p in ps], default=""),"confidence":"high","reason":"oracle stream window metadata only"})
    write_csv(ART/"pass654b_oracle_stream_windows.csv", win_rows, ["oracle_id","channel","flow_role","server_port","direction","window_sec","first_frame","last_frame","packet_count","total_bytes","stream_offset_start","stream_offset_end","largest_packet_len","confidence","reason"])
    print({"stream_rows":len(index_rows),"window_rows":len(win_rows)})
if __name__=="__main__": main()
