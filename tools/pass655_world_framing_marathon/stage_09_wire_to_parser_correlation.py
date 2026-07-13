#!/usr/bin/env python3
from pass655_common import *
def main():
    frames=read_csv(ART/"pass655_frame_models_top.csv"); fields=read_csv(ART/"pass655_candidate_field_models.csv"); repeats=read_csv(ART/"pass655_repeat_candidate_ranking.csv"); chans=read_csv(ART/"pass655_channel_field_candidates.csv"); constraints=read_csv(ART/"pass655_existing_parser_map.csv")
    byfield=defaultdict(list); byrep={r["model_id"]:r for r in repeats}; bychan=defaultdict(list)
    for f in fields: byfield[f["model_id"]].append(f)
    for c in chans: bychan[c["model_id"]].append(c)
    rows=[]; cid=1
    for f in frames[:50]:
        bestf=max(byfield.get(f["model_id"],[]), key=lambda x:float(x["score"]), default={})
        rep=float(byrep.get(f["model_id"],{}).get("repeat_score",0) or 0); chan=1.0 if bychan.get(f["model_id"]) else 0.0; parser=min(1.0,len(constraints)/8)
        total=round(float(f["global_score"])*0.35 + rep*25 + chan*20 + parser*10,3)
        rows.append({"combined_model_id":f"cm{cid:03d}","frame_model_id":f["model_id"],"header_size":f["header_size"],"length_rule":f"off{f['length_field_offset']}_w{f['length_width']}_{f['endianness']}","message_type_field":bestf.get("field_offset","") if bestf else "","channel_field":"candidate" if chan else "","body_start":f["header_size"],"repeat_score":rep,"channel_score":chan,"parser_constraint_score":round(parser,3),"negative_control_score":0.5,"total_score":total,"confidence":"medium" if total>25 else "low","reason":"coherent model rank combining framing, field, repeat, channel, and existing parser constraints"}); cid+=1
    rows=sorted(rows,key=lambda r:float(r["total_score"]),reverse=True)[:20]
    safe_write_csv(ART/"pass655_wire_parser_models.csv", rows, ["combined_model_id","frame_model_id","header_size","length_rule","message_type_field","channel_field","body_start","repeat_score","channel_score","parser_constraint_score","negative_control_score","total_score","confidence","reason"])
    print({"stage":"09","combined":len(rows)})
if __name__=="__main__": main()
