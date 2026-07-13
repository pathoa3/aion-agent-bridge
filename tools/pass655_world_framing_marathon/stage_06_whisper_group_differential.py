#!/usr/bin/env python3
from pass655_common import *
def main():
    packets=parse_pcapng(PCAP); world=detect_world_port(packets); ors=authoritative_oracles(); top=read_csv(ART/"pass655_frame_models_top.csv")[:50]
    wh=defaultdict(list); gr=defaultdict(list)
    for o in ors:
        if o["channel"]=="whisper": wh[base_marker(o["visible_text"])].append(o)
        if o["channel"]=="group": gr[base_marker(o["visible_text"])].append(o)
    models=[]; fields=[]
    for m in top:
        for b in sorted(set(wh)&set(gr)):
            wtot=[]; gtot=[]; wseq=[]; gseq=[]
            for o in wh[b]:
                ps=window_pkts(packets,world,"S2C",o["ts_mid"],3); wtot.append(sum(p.payload_len for p in ps)); wseq.append("-".join(str(p.payload_len) for p in ps[:8]))
            for o in gr[b]:
                ps=window_pkts(packets,world,"S2C",o["ts_mid"],3); gtot.append(sum(p.payload_len for p in ps)); gseq.append("-".join(str(p.payload_len) for p in ps[:8]))
            diff=bool(wtot and gtot and median(wtot)!=median(gtot)); repeat=bool(len(set(wseq))<=1 and len(set(gseq))<=1)
            models.append({"model_id":m["model_id"],"base_marker":b,"whisper_oracles":";".join(o["oracle_id"] for o in wh[b]),"group_oracles":";".join(o["oracle_id"] for o in gr[b]),"message_type_signal":bools(diff),"channel_field_signal":bools(diff and repeat),"one_char_body_length_signal":bools(abs((median(gtot) or 0)-(median(wtot) or 0)) in (0,1,2,4,8,16)),"sender_similarity_signal":bools(repeat),"packet_sequence_difference":bools(set(wseq)!=set(gseq)),"cross_flow_difference":"not_primary","confidence":"medium" if diff or repeat else "low","reason":"whisper/group base-ladder comparison over repeated oracle windows"})
            if diff and repeat:
                fields.append({"model_id":m["model_id"],"candidate_field":"channel_or_message_type","base_marker":b,"supporting_whisper_oracles":";".join(o["oracle_id"] for o in wh[b]),"supporting_group_oracles":";".join(o["oracle_id"] for o in gr[b]),"repetition_supported":bools(repeat),"confidence":"medium","reason":"repeated whisper/group windows diverge consistently at metadata level"})
    safe_write_csv(ART/"pass655_whisper_group_models.csv", models, ["model_id","base_marker","whisper_oracles","group_oracles","message_type_signal","channel_field_signal","one_char_body_length_signal","sender_similarity_signal","packet_sequence_difference","cross_flow_difference","confidence","reason"])
    safe_write_csv(ART/"pass655_channel_field_candidates.csv", fields, ["model_id","candidate_field","base_marker","supporting_whisper_oracles","supporting_group_oracles","repetition_supported","confidence","reason"])
    print({"stage":"06","models":len(models),"fields":len(fields)})
if __name__=="__main__": main()
