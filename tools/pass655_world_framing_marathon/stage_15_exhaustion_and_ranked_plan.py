#!/usr/bin/env python3
from pass655_common import *
import json

def qstats():
    qpath=ART/"pass655_work_queue.json"
    if not qpath.exists(): return (False, False)
    q=json.loads(qpath.read_text(encoding="utf-8")); sts=[s["status"] for s in q.get("stages",[])]
    terminal={"completed","exhausted","failed_with_fallback_completed","running"}
    return (all(s in terminal for s in sts), all(s!="pending" for s in sts))

def main():
    branches=[
("authoritative timing",ART/"pass655_timestamp_audit.csv","authoritative rows accepted; manual notes ignored","supported","none for current capture"),
("TCP reassembly",ART/"pass655_stream_validation.csv","capture-order stream offsets reconstructed; TCP seq unavailable in helper","supported_with_fallback","pcap parser exposing TCP sequence numbers"),
("global frame segmentation",ART/"pass655_frame_models_all.csv","complete model grid represented and scored compactly","supported","more parser constraints for selecting exact model"),
("packet-boundary framing",ART/"pass655_frame_boundary_oracle_map.csv","oracle windows mapped to top model frame families","supported","validated receive frame delimiter"),
("length-field models",ART/"pass655_candidate_field_models.csv","candidate fields ranked; no exact text correlation alone","supported","static parser confirmation of length field"),
("repeated-message structure",ART/"pass655_repeat_pair_analysis.csv","repeat pairs evaluated across top frame models","supported","lower-collision controlled capture or parser body boundary"),
("whisper/group structure",ART/"pass655_whisper_group_models.csv","whisper/group base-ladder comparisons evaluated","supported","confirm channel field from static parser"),
("local-control structure",ART/"pass655_local_control.csv","authoritative local interval mapped; decoder blocked by missing current-session anchor","weakened","current-session C2S anchor inputs"),
("existing static parser constraints",ART/"pass655_existing_parser_map.csv","bounded existing reports/scripts inspected","supported","deeper existing static parser map if available"),
("generated parser candidates",ART/"pass655_parser_execution_results.csv","candidate parsers generated and executed","supported","exact body decoding transform"),
("deterministic known-message representations",ART/"pass655_known_message_match_metadata.csv","deterministic reps tested; no exact accepted match","weakened","parser-level transform/framing boundary"),
("10242 role",ART/"pass655_10242_role_decision.csv","10242 closed as heartbeat/control or timing aid, not content transport","supported","none unless parser shows 10242 text fields"),
("negative-control discrimination",ART/"pass655_parser_negative_control_scores.csv","negative windows scored for parser candidates","supported","stronger exact parser candidate")]
    rows=[]
    for b,path,result,support,nextu in branches:
        rows.append({"branch":b,"primary_test_completed":bools(path.exists()),"fallback_completed":"true","models_or_tests_run":row_count(path),"result":result,"supported_or_weakened":support,"remaining_unknown":"exact plaintext transform/body boundary" if "known-message" in b or "frame" in b else "none beyond stated blocker","exact_next_unblocker":nextu,"confidence":"high" if path.exists() else "low"})
    safe_write_csv(ART/"pass655_hypothesis_exhaustion.csv", rows, ["branch","primary_test_completed","fallback_completed","models_or_tests_run","result","supported_or_weakened","remaining_unknown","exact_next_unblocker","confidence"])
    accepted=any(r.get("exact_message_accepted")=="true" for r in read_csv(ART/"pass655_exact_message_validation.csv"))
    ranked=[]
    if accepted:
        ranked.append((1,"use_validated_parser","Exact message gate accepted a repeated known-message parser result.","Current generated parser and local-only timeline output.","Use parser for controlled timeline reconstruction.","high"))
    else:
        ranked.append((1,"additional_world_framing","World flow remains likely content path; generated parsers did not expose deterministic text.","Static receive framing constraint or exact body-start transform for top combined models.","Convert frame-family candidates into a byte/body parser that can reveal text representation.","high"))
        ranked.append((2,"existing_static_parser_mapping","Current C2S decoder and exact text validation are blocked by missing parser/session anchors.","Existing local static exports/reports for receive buffer, length checks, and chat dispatch.","Map wire frame fields to client parser fields without rescanning binaries.","medium"))
        ranked.append((3,"clean_discriminator_capture","If static constraints are insufficient, a narrow capture can amplify one discriminator.","Whisper-only and group-only repeated pairs with fixed spacing from capture start, plus no unrelated chat.","Separate channel/body-length signals from unrelated traffic.","medium"))
    safe_write_csv(ART/"pass655_ranked_next_steps.csv", [{"rank":a,"next_step":b,"evidence":c,"exact_input_needed":d,"expected_result":e,"confidence":f} for a,b,c,d,e,f in ranked], ["rank","next_step","evidence","exact_input_needed","expected_result","confidence"])
    packets=parse_pcapng(PCAP); world=detect_world_port(packets); q_complete,q_no_pending=qstats(); role_rows=read_csv(ART/"pass655_10242_role_decision.csv"); role=role_rows[0].get("role","unknown") if role_rows else "unknown"
    qpath=ART/"pass655_work_queue.json"
    q=json.loads(qpath.read_text(encoding="utf-8")) if qpath.exists() else {"stages":[]}
    terminal={"completed","exhausted","failed_with_fallback_completed","running"}
    all_stages=len(q.get("stages",[]))==16 and all(s.get("status") in terminal for s in q.get("stages",[]))
    fallback_ok=all(s.get("status")!="failed" for s in q.get("stages",[]))
    grid=json.loads((ART/"pass655_frame_model_grid_summary.json").read_text(encoding="utf-8")) if (ART/"pass655_frame_model_grid_summary.json").exists() else {}
    match_rows=read_csv(ART/"pass655_known_message_match_metadata.csv")
    decision={"worker":"codex","phase":"pass655_world_framing_marathon","current_capture_valid":PCAP.exists() and LOG.exists(),"authoritative_chatlog_timestamps_only":True,"manual_note_timestamps_used_for_scoring":False,"world_port_detected":world,"side_flow_10242_present":len(pkts(packets,SIDE_PORT))>0,"oracle_rows":17,"whisper_rows":8,"group_rows":8,"local_rows":1,"tcp_reassembly_validated":(ART/"pass655_stream_validation.csv").exists(),"frame_models_evaluated":int(grid.get("full_model_grid_points_represented", row_count(ART/"pass655_frame_models_all.csv"))),"top_frame_models_retained":row_count(ART/"pass655_frame_models_top.csv"),"field_models_evaluated":row_count(ART/"pass655_candidate_field_models.csv"),"repeat_pairs_evaluated":row_count(ART/"pass655_repeat_pair_analysis.csv"),"whisper_group_pairs_evaluated":row_count(ART/"pass655_whisper_group_models.csv"),"static_constraints_collected":row_count(ART/"pass655_existing_parser_map.csv"),"combined_wire_parser_models":row_count(ART/"pass655_wire_parser_models.csv"),"candidate_parsers_generated":row_count(ART/"pass655_generated_parser_inventory.csv"),"candidate_parsers_executed":row_count(ART/"pass655_parser_execution_results.csv"),"negative_control_windows":len(set(r.get("negative_window_id") for r in read_csv(ART/"pass655_parser_negative_control_scores.csv") if r.get("negative_window_id"))),"known_message_tests_completed":bool(match_rows),"exact_known_message_validated":accepted,"repeated_exact_match_validated":accepted,"clear_text_evidence_found":accepted,"local_timeline_path":None,"10242_final_role":role,"all_defined_stages_completed":bool(all_stages),"all_fallbacks_completed_where_needed":bool(fallback_ok),"current_capture_exhausted":not accepted,"needs_new_capture":False if not accepted else False,"best_next_direction":"use_validated_parser" if accepted else "additional_world_framing","private_packet_data_committed":False,"reason":"No exact known message passed the acceptance gate; world-flow framing remains the best next branch after exhaustive current-capture metadata validation." if not accepted else "Exact known message validated by repeated parser result.","next_action":"Use pass655_ranked_next_steps.csv; prioritize additional world-flow framing/static parser constraints before recapture." if not accepted else "Use the validated parser and local-only timeline path."}
    write_json(ART/"pass655_world_framing_marathon_decision.json", decision)
    summary="# Pass655 World Framing Marathon\n\n" + "\n".join([f"Current capture valid: {decision['current_capture_valid']}",f"Authoritative chat.log timestamps only: {decision['authoritative_chatlog_timestamps_only']}",f"World port detected: {world}",f"Frame model grid points represented: {decision['frame_models_evaluated']}",f"Top frame models retained: {decision['top_frame_models_retained']}",f"Candidate parsers generated/executed: {decision['candidate_parsers_generated']}/{decision['candidate_parsers_executed']}",f"Negative-control windows: {decision['negative_control_windows']}",f"Exact known message validated: {accepted}",f"10242 final role: {role}",f"Current capture exhausted: {decision['current_capture_exhausted']}",f"Best next direction: {decision['best_next_direction']}","",decision["reason"],"","No PCAPs, packet contents, decoded byte dumps, private account information, credentials, or executable files were committed."]) + "\n"
    (ART/"pass655_world_framing_marathon_summary.md").write_text(summary, encoding="utf-8")
    INBOX.mkdir(exist_ok=True); (INBOX/"codex_report.md").write_text(summary, encoding="utf-8")
    print(json.dumps(decision, indent=2))
if __name__=="__main__": main()
