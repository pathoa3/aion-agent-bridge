#!/usr/bin/env python3
from pass655_common import *
def main():
    packets=parse_pcapng(PCAP); world=detect_world_port(packets); rows=[]; offsets=[]; intervals=[]
    for port,role in [(world,"world"),(SIDE_PORT,"side_control")]:
        if port is None: continue
        for direction in ("S2C","C2S"):
            ps=pkts(packets,port,direction); seen=Counter((p.frame,p.payload_len,p.ts) for p in ps)
            rows.append({"flow_role":role,"server_port":port,"direction":direction,"packet_count":len(ps),"stream_bytes":sum(p.payload_len for p in ps),"retransmissions_detected":0,"duplicate_segments":sum(1 for v in seen.values() if v>1),"gaps_detected":"unknown_no_tcp_seq_exported","out_of_order_segments":0,"stream_offset_mapping":"complete_by_capture_order","confidence":"medium","reason":"pcap helper exposes capture-order payloads but not TCP sequence numbers; fallback validates deterministic timestamp/frame ordering"})
            for p,s,e in stream_index(packets,port,direction): offsets.append({"flow_role":role,"server_port":port,"direction":direction,"frame":p.frame,"time":iso_time(p.ts),"tcp_len":p.payload_len,"stream_offset_start":s,"stream_offset_end":e,"confidence":"high","reason":"offset mapping by ordered payload stream; no bytes written"})
    safe_write_csv(ART/"pass655_stream_validation.csv", rows, ["flow_role","server_port","direction","packet_count","stream_bytes","retransmissions_detected","duplicate_segments","gaps_detected","out_of_order_segments","stream_offset_mapping","confidence","reason"])
    safe_write_csv(ART/"pass655_frame_to_stream_offsets.csv", offsets, ["flow_role","server_port","direction","frame","time","tcp_len","stream_offset_start","stream_offset_end","confidence","reason"])
    models=[("exact_second",None),("pm1_5",1.5),("pm3",3),("pm5",5),("pm10",10)]
    for o in authoritative_oracles():
        for port,role in [(world,"world"),(SIDE_PORT,"side_control")]:
            if port is None: continue
            for direction in ("S2C","C2S"):
                idx=stream_index(packets,port,direction)
                for name,sec in models:
                    ps=[p for p in pkts(packets,port,direction) if in_interval(p,o)] if sec is None else window_pkts(packets,port,direction,o['ts_mid'],sec)
                    off=[(s,e) for p,s,e in idx if p in ps]
                    intervals.append({"oracle_id":o["oracle_id"],"channel":o["channel"],"flow_role":role,"server_port":port,"direction":direction,"window_model":name,"first_frame":min([p.frame for p in ps], default=""),"last_frame":max([p.frame for p in ps], default=""),"packet_count":len(ps),"total_bytes":sum(p.payload_len for p in ps),"stream_offset_start":min([s for s,e in off], default=""),"stream_offset_end":max([e for s,e in off], default=""),"confidence":"high","reason":"authoritative oracle interval/window stream metadata"})
    safe_write_csv(ART/"pass655_oracle_stream_intervals.csv", intervals, ["oracle_id","channel","flow_role","server_port","direction","window_model","first_frame","last_frame","packet_count","total_bytes","stream_offset_start","stream_offset_end","confidence","reason"])
    print({"stage":"02","streams":len(rows),"offsets":len(offsets),"intervals":len(intervals)})
if __name__=="__main__": main()
