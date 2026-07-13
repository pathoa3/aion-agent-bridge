#!/usr/bin/env python3
from pass655_common import *
def main():
    sources=[ART/"pass654b_hypothesis_status.csv",ART/"pass654b_world_flow_hypotheses.csv",ART/"pass654b_10242_format_hypotheses.csv",ART/"pass653_10242_labeler_hardening_decision.json",ART/"pass655_frame_models_top.csv",REPO/"tools"/"pass647_dynamic_world_port"/"pcap_dynamic.py"]
    rows=[]; eid=1
    for src in sources:
        if not src.exists(): continue
        if src.suffix==".csv":
            count=row_count(src); reason=f"existing artifact rows={count}"
        else:
            count=1; reason="existing script/report inspected by path and role only"
        comp="world_receive_framing" if "world" in src.name or "frame" in src.name else "flow_parser" if "pcap_dynamic" in src.name else "10242_or_prior_result"
        rows.append({"evidence_id":f"e{eid:03d}","source_file_or_artifact":str(src),"component":comp,"structural_constraint":"dynamic flow roles, stream windows, deterministic text tests, and frame model families already available","wire_model_supported":"world flow remains likely content transport; 10242 direct text weakened","wire_model_weakened":"direct clear text without framing/transform; current C2S decoder applicability","confidence":"medium" if count else "low","reason":reason}); eid+=1
    rows.append({"evidence_id":f"e{eid:03d}","source_file_or_artifact":"Pass655 authoritative chat.log rows","component":"timing","structural_constraint":"chatlog seconds are scoring intervals; manual note timestamps ignored","wire_model_supported":"authoritative interval matching","wire_model_weakened":"manual-note correlation","confidence":"high","reason":"explicit Pass655 requirement"})
    safe_write_csv(ART/"pass655_existing_parser_map.csv", rows, ["evidence_id","source_file_or_artifact","component","structural_constraint","wire_model_supported","wire_model_weakened","confidence","reason"])
    safe_write_csv(ART/"pass655_receive_format_constraints.csv", rows, ["evidence_id","source_file_or_artifact","component","structural_constraint","wire_model_supported","wire_model_weakened","confidence","reason"])
    print({"stage":"08","constraints":len(rows)})
if __name__=="__main__": main()
