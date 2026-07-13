#!/usr/bin/env python3
from pass655_common import *
def main():
    rows=authoritative_oracles()
    out=[{k:r[k] for k in ["oracle_id","channel","speaker","visible_text","text_length","chatlog_second_start","chatlog_second_end","primary_source","manual_note_present","manual_note_used_for_scoring","strong_reference","reason"]} for r in rows]
    safe_write_csv(ART/"pass655_authoritative_oracles.csv", out, ["oracle_id","channel","speaker","visible_text","text_length","chatlog_second_start","chatlog_second_end","primary_source","manual_note_present","manual_note_used_for_scoring","strong_reference","reason"])
    ok=len(rows)==17 and sum(r["channel"]=="whisper" for r in rows)==8 and sum(r["channel"]=="group" for r in rows)==8 and sum(r["channel"]=="local" for r in rows)==1 and not any(r["manual_note_used_for_scoring"] for r in rows)
    local=[r for r in rows if r["channel"]=="local"][0]
    audit=[{"check_name":"row_count_17","result":bools(len(rows)==17),"confidence":"high","reason":f"rows={len(rows)}"},{"check_name":"whisper_count_8","result":bools(sum(r['channel']=='whisper' for r in rows)==8),"confidence":"high","reason":"authoritative rows only"},{"check_name":"group_count_8","result":bools(sum(r['channel']=='group' for r in rows)==8),"confidence":"high","reason":"authoritative rows only"},{"check_name":"local_count_1","result":bools(sum(r['channel']=='local' for r in rows)==1),"confidence":"high","reason":"authoritative rows only"},{"check_name":"manual_notes_not_used","result":bools(not any(r['manual_note_used_for_scoring'] for r in rows)),"confidence":"high","reason":"manual log_s2c_marker.ps1 times ignored"},{"check_name":"local_interval_near_212430","result":bools(local['chatlog_second_start'].startswith('2026-07-13 21:24:30')),"confidence":"high","reason":local['chatlog_second_start']},{"check_name":"stage_00_acceptance","result":bools(ok),"confidence":"high" if ok else "low","reason":"must pass before later stages"}]
    safe_write_csv(ART/"pass655_timestamp_audit.csv", audit, ["check_name","result","confidence","reason"])
    if not ok: raise SystemExit(2)
    print({"stage":"00","rows":len(rows),"accepted":ok})
if __name__=="__main__": main()
