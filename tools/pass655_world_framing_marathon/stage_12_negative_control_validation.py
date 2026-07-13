#!/usr/bin/env python3
from pass655_common import *
def main():
    packets=parse_pcapng(PCAP); world=detect_world_port(packets); models=read_csv(ART/"pass655_wire_parser_models.csv"); rows=[]; mid=1
    negs=[r for r in read_csv(ART/"pass655_parser_negative_control_scores.csv") if r.get("negative_window_id")]
    for m in models:
        for o in authoritative_oracles():
            data=b"".join(p.payload for p in window_pkts(packets,world,"S2C",o["ts_mid"],3))
            hit_msg=hit_sender=hit_chan=False; rep_hit="none"
            for rep,needle in message_reps(o["visible_text"],o["speaker"],o["channel"]):
                if needle and data.find(needle)>=0:
                    rep_hit=rep
                    if rep in ("ascii","utf16le","utf16be","nul_ascii","no_underscore","sender_marker_ascii","sender_marker_utf16le","channel_sender_marker_ascii","channel_sender_marker_utf16le"): hit_msg=True
                    if "sender" in rep: hit_sender=True
                    if "channel" in rep: hit_chan=True
                    break
            repeat=False
            if hit_msg:
                same=[x for x in authoritative_oracles() if x["visible_text"]==o["visible_text"]]
                repeat=len(same)>=2
            conflicts=sum(1 for n in negs if n["parser_id"]==m["combined_model_id"] and float(n.get("negative_score") or 0)>0.8)
            rows.append({"match_id":f"km{mid:05d}","combined_model_id":m["combined_model_id"],"oracle_id":o["oracle_id"],"channel":o["channel"],"representation":rep_hit,"frame_count":len(window_pkts(packets,world,"S2C",o["ts_mid"],3)),"exact_message_match":bools(hit_msg),"exact_sender_match":bools(hit_sender),"exact_channel_match":bools(hit_chan),"repeat_validated":bools(repeat),"negative_control_conflicts":conflicts,"local_detail_path":"","confidence":"high" if hit_msg and repeat and conflicts==0 else "low","reason":"deterministic representation tests on structurally viable candidate windows; no bytes committed"}); mid+=1
    safe_write_csv(ART/"pass655_known_message_match_metadata.csv", rows, ["match_id","combined_model_id","oracle_id","channel","representation","frame_count","exact_message_match","exact_sender_match","exact_channel_match","repeat_validated","negative_control_conflicts","local_detail_path","confidence","reason"])
    print({"stage":"12","tests":len(rows),"exact":sum(1 for r in rows if r['exact_message_match']=='true')})
if __name__=="__main__": main()
