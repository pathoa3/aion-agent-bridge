#!/usr/bin/env python3
from common import *
def main():
    tests=read_csv(ART/"pass654b_known_text_tests.csv"); rows=[]
    exact=[r for r in tests if r.get("exact_message_match")=="true"]
    byflow=defaultdict(list)
    for r in exact: byflow[(r["flow_role"],r["server_port"],r["direction"],r["representation"])].append(r)
    cid=1
    for key,vals in byflow.items():
        oids={v["oracle_id"] for v in vals}; oracle_rows=[o for o in merged_oracles() if o["oracle_id"] in oids]
        unrelated=sum(1 for r in vals if r.get("channel") not in ("whisper","group","local"))
        rows.append({"candidate_id":f"c{cid:03d}","source_stage":"stage_e_known_text_location","oracle_rows_supported":len(oids),"repeated_rows_supported":sum(1 for txt in Counter(o["visible_text"] for o in oracle_rows).values() if txt>=2),"whisper_supported":bools(any(o["channel"]=="whisper" for o in oracle_rows)),"group_supported":bools(any(o["channel"]=="group" for o in oracle_rows)),"local_supported":bools(any(o["channel"]=="local" for o in oracle_rows)),"unrelated_window_conflicts":unrelated,"exact_text_validated":bools(len(oids)>=2 and unrelated==0),"confidence":"high" if len(oids)>=2 and unrelated==0 else "medium","reason":"candidate exact match requires repeated known rows and no unrelated conflicts"}); cid+=1
    if not rows:
        rows.append({"candidate_id":"none","source_stage":"stage_e_known_text_location","oracle_rows_supported":0,"repeated_rows_supported":0,"whisper_supported":"false","group_supported":"false","local_supported":"false","unrelated_window_conflicts":0,"exact_text_validated":"false","confidence":"high","reason":"no exact known-message candidates found in deterministic matrix"})
    write_csv(ART/"pass654b_candidate_validation.csv", rows, ["candidate_id","source_stage","oracle_rows_supported","repeated_rows_supported","whisper_supported","group_supported","local_supported","unrelated_window_conflicts","exact_text_validated","confidence","reason"])
    print({"candidate_rows":len(rows)})
if __name__=="__main__": main()
