#!/usr/bin/env python3
from common import *
def main():
    packets=parse_pcapng(PCAP); world=detect_world_port(packets); oracles=[o for o in merged_oracles() if o["current_capture"]]
    rows=[]; hyp=[]
    for direction in ("S2C","C2S"):
        pks=pkts(packets,world,direction) if world else []
        for win,sec in [("nearest",0),("pm1",1),("pm3",3),("pm5",5),("pm10",10)]:
            subset=[]
            for o in oracles:
                ps=[nearest(pks,o["ts"])] if sec==0 else window_pkts(packets,world,o["ts"],sec,direction) if world else []
                ps=[p for p in ps if p]
                subset.append((o,ps,sum(p.payload_len for p in ps),max([p.payload_len for p in ps], default=0)))
            bychan=defaultdict(list)
            for o,ps,total,largest in subset: bychan[o["channel"]].append(total)
            chan_sig=bool(bychan.get("whisper") and bychan.get("group") and median(bychan["whisper"])!=median(bychan["group"]))
            exact=any(r.get("exact_message_match")=="true" and r.get("server_port")==str(world) and r.get("direction")==direction for r in read_csv(ART/"pass654b_known_text_tests.csv"))
            hyp.append({"hypothesis_id":f"world_{direction}_{win}","channel":"all","direction":direction,"window_model":win,"header_model":"offset_0_32_metadata","rows_tested":len(subset),"rows_plausible":sum(1 for _o,ps,_t,_l in subset if ps),"repeat_consistent":"pending","message_length_signal":bools(len(set(t for _o,_ps,t,_l in subset))>1),"channel_signal":bools(chan_sig),"exact_text_match":bools(exact),"confidence":"medium" if subset else "low","reason":"world-flow oracle windows analyzed using packet/stream metadata and deterministic text-test results"})
            for o,ps,total,largest in subset:
                rows.append({"hypothesis_id":f"world_{direction}_{win}_{o['oracle_id']}","channel":o["channel"],"direction":direction,"window_model":win,"header_model":"offset_0_32_metadata","rows_tested":1,"rows_plausible":1 if ps else 0,"repeat_consistent":"pending","message_length_signal":bools(total>0),"channel_signal":bools(chan_sig),"exact_text_match":bools(exact),"confidence":"medium","reason":f"packet_count={len(ps)} total_bytes={total} largest={largest}"})
    write_csv(ART/"pass654b_world_flow_hypotheses.csv", hyp, ["hypothesis_id","channel","direction","window_model","header_model","rows_tested","rows_plausible","repeat_consistent","message_length_signal","channel_signal","exact_text_match","confidence","reason"])
    write_csv(ART/"pass654b_world_flow_oracle_windows.csv", rows, ["hypothesis_id","channel","direction","window_model","header_model","rows_tested","rows_plausible","repeat_consistent","message_length_signal","channel_signal","exact_text_match","confidence","reason"])
    print({"world_hypotheses":len(hyp),"world_windows":len(rows)})
if __name__=="__main__": main()
