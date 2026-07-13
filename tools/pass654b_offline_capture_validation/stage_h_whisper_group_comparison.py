#!/usr/bin/env python3
from common import *
def base_id(txt):
    t=txt[:-1] if txt.endswith("G") else txt
    parts=t.split("_")
    return parts[2] if len(parts)>2 else t

def main():
    packets=parse_pcapng(PCAP); world=detect_world_port(packets); oracles=[o for o in merged_oracles() if o["current_capture"]]
    whispers=defaultdict(list); groups=defaultdict(list)
    for o in oracles:
        if o["channel"]=="whisper": whispers[base_id(o["visible_text"])].append(o)
        if o["channel"]=="group": groups[base_id(o["visible_text"])].append(o)
    rows=[]; pid=1
    for bid in sorted(set(whispers)&set(groups)):
        for port,role in [(world,"world"),(SIDE_PORT,"event_side")]:
            if port is None: continue
            for direction in ("S2C","C2S"):
                for feat in ("nearest_len","pm3_total_bytes","pm3_packet_count","pm3_direction_sequence"):
                    wvals=[]; gvals=[]
                    for o in whispers[bid]:
                        ps=window_pkts(packets,port,o["ts"],3,direction); n=nearest(pkts(packets,port,direction),o["ts"])
                        lens,dirs,total=length_seq(pkts(packets,port),o["ts"],3)
                        wvals.append(n.payload_len if feat=="nearest_len" and n else total if feat=="pm3_total_bytes" else len(ps) if feat=="pm3_packet_count" else dirs)
                    for o in groups[bid]:
                        ps=window_pkts(packets,port,o["ts"],3,direction); n=nearest(pkts(packets,port,direction),o["ts"])
                        lens,dirs,total=length_seq(pkts(packets,port),o["ts"],3)
                        gvals.append(n.payload_len if feat=="nearest_len" and n else total if feat=="pm3_total_bytes" else len(ps) if feat=="pm3_packet_count" else dirs)
                    diff=bool(wvals and gvals and median([v for v in wvals if isinstance(v,int)])!=median([v for v in gvals if isinstance(v,int)])) if feat!="pm3_direction_sequence" else bool(set(wvals)!=set(gvals))
                    repeat=bool(len(set(wvals))<=1 and len(set(gvals))<=1 and wvals and gvals)
                    rows.append({"pair_id":f"p{pid:03d}","base_marker":bid,"whisper_oracles":";".join(o["oracle_id"] for o in whispers[bid]),"group_oracles":";".join(o["oracle_id"] for o in groups[bid]),"flow_role":role,"server_port":port,"direction":direction,"feature_name":feat,"whisper_feature":"|".join(map(str,wvals)),"group_feature":"|".join(map(str,gvals)),"difference_found":bools(diff),"repeat_supported":bools(repeat),"confidence":"medium" if diff or repeat else "low","reason":"controlled whisper/group comparison by base marker id"}); pid+=1
    write_csv(ART/"pass654b_whisper_group_differential.csv", rows, ["pair_id","base_marker","whisper_oracles","group_oracles","flow_role","server_port","direction","feature_name","whisper_feature","group_feature","difference_found","repeat_supported","confidence","reason"])
    print({"differential_rows":len(rows)})
if __name__=="__main__": main()
