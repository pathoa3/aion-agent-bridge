#!/usr/bin/env python3
from pass655_common import *
def pair_groups():
    groups=defaultdict(list)
    for o in authoritative_oracles():
        if o["channel"] in ("whisper","group"): groups[(o["channel"],o["visible_text"])].append(o)
    return [(k,v) for k,v in groups.items() if len(v)>=2]

def sig(packets, port, o):
    ps=window_pkts(packets,port,"S2C",o["ts_mid"],3)
    lens="-".join(str(p.payload_len) for p in ps[:8]); total=sum(p.payload_len for p in ps)
    return len(ps),total,lens

def main():
    packets=parse_pcapng(PCAP); world=detect_world_port(packets); top=read_csv(ART/"pass655_frame_models_top.csv")[:50]
    rows=[]; ranks=[]
    for m in top:
        stable=0; total_pairs=0; collisions=0
        for (chan,text),pair in pair_groups():
            a,b=pair[0],pair[1]; sa=sig(packets,world,a); sb=sig(packets,world,b); total_pairs+=1
            rep=(sa[0]==sb[0] and sa[2]==sb[2]); stable+=1 if rep else 0
            collisions += 0 if rep else 1
            rows.append({"model_id":m["model_id"],"pair_name":f"{chan}_{base_marker(text)}","oracle_a":a["oracle_id"],"oracle_b":b["oracle_id"],"frame_count_a":sa[0],"frame_count_b":sb[0],"total_bytes_a":sa[1],"total_bytes_b":sb[1],"length_sequence_a":sa[2],"length_sequence_b":sb[2],"repeat_consistent":bools(rep),"unrelated_window_collision_rate":round(collisions/max(1,total_pairs),3),"confidence":"medium" if rep else "low","reason":"repeated identical message compared against world S2C +/-3s packet/burst signature"})
        ranks.append({"model_id":m["model_id"],"repeat_pairs_tested":total_pairs,"repeat_pairs_consistent":stable,"unrelated_window_collision_rate":round(collisions/max(1,total_pairs),3),"repeat_score":round(stable/max(1,total_pairs),3),"confidence":"medium" if stable else "low","reason":"candidate ranking by repeated-message consistency versus collision proxy"})
    safe_write_csv(ART/"pass655_repeat_pair_analysis.csv", rows, ["model_id","pair_name","oracle_a","oracle_b","frame_count_a","frame_count_b","total_bytes_a","total_bytes_b","length_sequence_a","length_sequence_b","repeat_consistent","unrelated_window_collision_rate","confidence","reason"])
    safe_write_csv(ART/"pass655_repeat_candidate_ranking.csv", sorted(ranks,key=lambda r:float(r["repeat_score"]),reverse=True), ["model_id","repeat_pairs_tested","repeat_pairs_consistent","unrelated_window_collision_rate","repeat_score","confidence","reason"])
    print({"stage":"05","rows":len(rows),"ranked":len(ranks)})
if __name__=="__main__": main()
