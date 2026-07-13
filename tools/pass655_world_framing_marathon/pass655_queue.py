#!/usr/bin/env python3
from __future__ import annotations
import json, sys, subprocess, datetime as dt
from pathlib import Path
from pass655_common import ART, REPO, TOOL, write_json

QUEUE = ART / "pass655_work_queue.json"
STAGES = [
 ("stage_00_timestamp_repair","tools/pass655_world_framing_marathon/stage_00_timestamp_repair.py"),
 ("stage_01_capture_and_stream_audit","tools/pass655_world_framing_marathon/stage_01_capture_and_stream_audit.py"),
 ("stage_02_tcp_reassembly_validation","tools/pass655_world_framing_marathon/stage_02_tcp_reassembly_validation.py"),
 ("stage_03_frame_boundary_search","tools/pass655_world_framing_marathon/stage_03_frame_boundary_search.py"),
 ("stage_04_length_field_models","tools/pass655_world_framing_marathon/stage_04_length_field_models.py"),
 ("stage_05_repeated_message_differential","tools/pass655_world_framing_marathon/stage_05_repeated_message_differential.py"),
 ("stage_06_whisper_group_differential","tools/pass655_world_framing_marathon/stage_06_whisper_group_differential.py"),
 ("stage_07_local_control_analysis","tools/pass655_world_framing_marathon/stage_07_local_control_analysis.py"),
 ("stage_08_existing_static_export_mapping","tools/pass655_world_framing_marathon/stage_08_existing_static_export_mapping.py"),
 ("stage_09_wire_to_parser_correlation","tools/pass655_world_framing_marathon/stage_09_wire_to_parser_correlation.py"),
 ("stage_10_candidate_parser_generation","tools/pass655_world_framing_marathon/stage_10_candidate_parser_generation.py"),
 ("stage_11_candidate_parser_execution","tools/pass655_world_framing_marathon/stage_11_candidate_parser_execution.py"),
 ("stage_12_negative_control_validation","tools/pass655_world_framing_marathon/stage_12_negative_control_validation.py"),
 ("stage_13_10242_role_closure","tools/pass655_world_framing_marathon/stage_13_10242_role_closure.py"),
 ("stage_14_exact_message_validation","tools/pass655_world_framing_marathon/stage_14_exact_message_validation.py"),
 ("stage_15_exhaustion_and_ranked_plan","tools/pass655_world_framing_marathon/stage_15_exhaustion_and_ranked_plan.py"),
]
TERMINAL={"completed","exhausted","failed_with_fallback_completed"}

def load_queue():
    if QUEUE.exists(): return json.loads(QUEUE.read_text(encoding="utf-8"))
    return {"phase":"pass655_world_framing_marathon","updated":"","stages":[{"name":n,"script":s,"status":"pending","attempts":0,"fallback_completed":False,"last_error":""} for n,s in STAGES]}

def save_queue(q):
    q["updated"]=dt.datetime.now().isoformat(timespec="seconds")
    write_json(QUEUE,q)

def set_status(q,name,status,error="",fallback=False):
    for st in q["stages"]:
        if st["name"]==name:
            st["status"]=status; st["last_error"]=error; st["fallback_completed"]=bool(st.get("fallback_completed") or fallback)
            if status=="running": st["attempts"]=int(st.get("attempts",0))+1
    save_queue(q)

def next_stage(q):
    for st in q["stages"]:
        if st["status"] not in TERMINAL and st["status"]!="running": return st
    for st in q["stages"]:
        if st["status"]=="running": return st
    return None

def run_all():
    q=load_queue(); save_queue(q)
    while True:
        st=next_stage(q)
        if not st: break
        name=st["name"]; script=st["script"]
        set_status(q,name,"running")
        proc=subprocess.run([sys.executable, script], cwd=str(REPO), text=True, capture_output=True)
        if proc.stdout: print(proc.stdout, end="")
        if proc.returncode==0:
            q=load_queue(); set_status(q,name,"completed")
        else:
            err=(proc.stderr or proc.stdout or "stage failed")[-2000:]
            print(err, file=sys.stderr)
            # Defined fallback is to record the blocker and continue with safe metadata-only exhaustion.
            q=load_queue(); set_status(q,name,"failed_with_fallback_completed",err,True)
        q=load_queue()
    return 0

if __name__=="__main__": raise SystemExit(run_all())
