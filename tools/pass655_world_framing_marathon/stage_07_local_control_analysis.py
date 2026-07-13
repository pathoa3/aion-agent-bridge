#!/usr/bin/env python3
from pass655_common import *
def main():
    packets=parse_pcapng(PCAP); world=detect_world_port(packets); local=[o for o in authoritative_oracles() if o["channel"]=="local"][0]
    rows=[]
    for port,role in [(world,"world"),(SIDE_PORT,"side_control")]:
        for direction in ("C2S","S2C"):
            ps_exact=[p for p in pkts(packets,port,direction) if in_interval(p,local)] if port else []
            ps5=window_pkts(packets,port,direction,local["ts_mid"],5) if port else []
            exact=any(local["visible_text"].encode("ascii") in p.payload or local["visible_text"].encode("utf-16le") in p.payload for p in ps5)
            rows.append({"test_name":"local_control_authoritative_interval","flow_role":role,"server_port":port,"direction":direction,"authoritative_interval":f"{local['chatlog_second_start']}..{local['chatlog_second_end']}","exact_interval_packets":len(ps_exact),"pm5_packets":len(ps5),"exact_text_matched":bools(exact),"existing_decoder_applicable":"false","decoder_blocker":"missing_current_session_anchor_or_required_inputs" if direction=="C2S" else "not_a_c2s_decoder_path","confidence":"medium","reason":"local row mapped using authoritative 21:24:30 interval; no manual timestamp used"})
    safe_write_csv(ART/"pass655_local_control.csv", rows, ["test_name","flow_role","server_port","direction","authoritative_interval","exact_interval_packets","pm5_packets","exact_text_matched","existing_decoder_applicable","decoder_blocker","confidence","reason"])
    print({"stage":"07","rows":len(rows)})
if __name__=="__main__": main()
