#!/usr/bin/env python3
from common import *
def main():
    packets=parse_pcapng(PCAP); oracles=[o for o in merged_oracles() if o["current_capture"]]
    side=pkts(packets,SIDE_PORT); c2s=[p for p in side if p.direction_guess=="C2S"]; s2c=[p for p in side if p.direction_guess=="S2C"]
    intervals=[int(round((c2s[i].ts-c2s[i-1].ts)*1000)) for i in range(1,len(c2s))]
    heartbeat=(median([abs(i-median(intervals)) for i in intervals])==0 and median(intervals)!="")
    comp=[]
    for o in oracles:
        nc=nearest(c2s,o["ts"]); ns=nearest(s2c,o["ts"]); lens,dirs,total=length_seq(side,o["ts"],3)
        comp.append({"oracle_id":o["oracle_id"],"channel":o["channel"],"nearest_c2s_frame":nc.frame if nc else "","c2s_delta_ms":delta_ms(nc,o["ts"]),"nearest_s2c_frame":ns.frame if ns else "","s2c_delta_ms":delta_ms(ns,o["ts"]),"window_length_sequence":lens,"direction_sequence":dirs,"repeat_match":"pending","channel_signal":bools(o["channel"]=="group" and total!=0),"confidence":"medium","reason":"10242 timing/length/direction comparison around oracle"})
    bytext=defaultdict(list)
    for r,o in zip(comp,oracles): bytext[o["visible_text"]].append(r["window_length_sequence"])
    for r,o in zip(comp,oracles): r["repeat_match"]=bools(len(set(bytext[o["visible_text"]]))==1 if len(bytext[o["visible_text"]])>1 else False)
    write_csv(ART/"pass654b_10242_oracle_comparison.csv", comp, ["oracle_id","channel","nearest_c2s_frame","c2s_delta_ms","nearest_s2c_frame","s2c_delta_ms","window_length_sequence","direction_sequence","repeat_match","channel_signal","confidence","reason"])
    direct=any(r.get("exact_message_match")=="true" and r.get("server_port")==str(SIDE_PORT) for r in read_csv(ART/"pass654b_known_text_tests.csv"))
    hyps=[
      ("h10242_heartbeat","C2S","fixed22_cadence","periodic 22-byte C2S",len(c2s),len(c2s),heartbeat,False,False,False,"high" if heartbeat else "medium","C2S packets show cadence model"),
      ("h10242_chat_metadata","both","timing_window","oracle-correlated metadata/burst signals",len(oracles),sum(1 for r in comp if r["nearest_c2s_frame"]),False,True,False,False,"medium","10242 aligns in time but does not expose text"),
      ("h10242_text_transport","S2C/C2S","deterministic_text","direct deterministic known-text search",len(oracles),sum(1 for r in read_csv(ART/"pass654b_known_text_tests.csv") if r.get("server_port")==str(SIDE_PORT) and r.get("hits")=="1"),False,False,False,direct,"low" if not direct else "high","exact text field support only if deterministic text hit exists")]
    rows=[{"hypothesis_id":a,"direction":b,"header_size":c,"field_layout":d,"rows_tested":e,"rows_plausible":f,"repeat_consistent":bools(g),"whisper_group_difference":bools(h),"message_length_signal":bools(i),"text_field_supported":bools(j),"confidence":k,"reason":l} for a,b,c,d,e,f,g,h,i,j,k,l in hyps]
    write_csv(ART/"pass654b_10242_format_hypotheses.csv", rows, ["hypothesis_id","direction","header_size","field_layout","rows_tested","rows_plausible","repeat_consistent","whisper_group_difference","message_length_signal","text_field_supported","confidence","reason"])
    print({"10242_hypotheses":len(rows)})
if __name__=="__main__": main()
