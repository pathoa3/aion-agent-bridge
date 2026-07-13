#!/usr/bin/env python3
from common import *
def main():
    packets=parse_pcapng(PCAP); world=detect_world_port(packets); oracles=[o for o in merged_oracles() if o["channel"]=="local"]
    rows=[]
    for o in oracles:
        for port,role in [(world,"world"),(SIDE_PORT,"event_side")]:
            if port is None: continue
            for direction in ("C2S","S2C"):
                data=bytes_for_window(packets,port,direction,o["ts"],10)
                exact=find_rep(data,o["visible_text"].encode("ascii",errors="ignore")) or find_rep(data,o["visible_text"].encode("utf-16le"))
                n=nearest(pkts(packets,port,direction),o["ts"])
                ev=nearest(pkts(packets,SIDE_PORT),o["ts"])
                rows.append({"test_name":"local_say_control","flow_role":role,"server_port":port,"direction":direction,"exact_text_matched":bools(exact),"existing_decoder_applicable":"false","frame":n.frame if n else "","time_delta_ms":delta_ms(n,o["ts"]),"corresponding_event_found":bools(ev is not None and abs(int(delta_ms(ev,o['ts']) or 999999))<=10000),"confidence":"medium","reason":"deterministic local control search; existing C2S decoder not applied because no validated session anchor material is available in committed metadata"})
    if not rows:
        rows.append({"test_name":"local_say_control","flow_role":"unknown","server_port":"","direction":"","exact_text_matched":"false","existing_decoder_applicable":"false","frame":"","time_delta_ms":"","corresponding_event_found":"false","confidence":"low","reason":"no local oracle row available"})
    write_csv(ART/"pass654b_local_message_control.csv", rows, ["test_name","flow_role","server_port","direction","exact_text_matched","existing_decoder_applicable","frame","time_delta_ms","corresponding_event_found","confidence","reason"])
    print({"local_control_rows":len(rows)})
if __name__=="__main__": main()
