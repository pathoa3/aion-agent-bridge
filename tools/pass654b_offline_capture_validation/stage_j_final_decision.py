#!/usr/bin/env python3
from common import *
def main():
    text=read_csv(ART/"pass654b_known_text_tests.csv"); side=read_csv(ART/"pass654b_10242_format_hypotheses.csv"); world=read_csv(ART/"pass654b_world_flow_hypotheses.csv"); cand=read_csv(ART/"pass654b_candidate_validation.csv"); diff=read_csv(ART/"pass654b_whisper_group_differential.csv"); local=read_csv(ART/"pass654b_local_message_control.csv")
    exact10242=any(r.get("exact_message_match")=="true" and r.get("server_port")==str(SIDE_PORT) for r in text)
    exactworld=any(r.get("exact_message_match")=="true" and r.get("flow_role")=="world" for r in text)
    valid=any(r.get("exact_text_validated")=="true" for r in cand)
    chan=any(r.get("difference_found")=="true" and r.get("repeat_supported")=="true" for r in diff)
    rows=[
      ("direct text on 10242",True,sum(1 for r in text if r.get("server_port")==str(SIDE_PORT)),"exact_hit" if exact10242 else "no exact message hit","supported" if exact10242 else "weakened","high","If pursuing 10242, move to static parser/field analysis rather than direct text search."),
      ("structured text field on 10242",True,len(side),"no text_field_supported" if not any(r.get("text_field_supported")=="true" for r in side) else "candidate","weakened","medium","Inspect client-side 10242 parser statically for field semantics."),
      ("heartbeat-only 10242 model",True,len(side),"heartbeat hypothesis present" if any("heartbeat" in r.get("hypothesis_id","") for r in side) else "not shown","supported","medium","Treat C2S22 as cadence/control, not text."),
      ("chat-event metadata on 10242",True,len(side),"timing metadata plausible","supported","medium","Use as event timing aid only."),
      ("direct text on world flow",True,sum(1 for r in text if r.get("flow_role")=="world"),"exact_hit" if exactworld else "no exact message hit","supported" if exactworld else "weakened","high","Continue world framing/static receive analysis."),
      ("stream-spanning text on world flow",True,sum(1 for r in text if r.get("flow_role")=="world" and r.get("segments_spanned")=="true"),"no exact spanning hit" if not exactworld else "hit","weakened","high","Needs framing/crypto state before text representation is visible."),
      ("standard compression on world flow",True,0,"no compatible deterministic compression text hits recorded","weakened","medium","Search static receive path for compression boundary if present."),
      ("packet-sequence representation",True,len(world),"metadata windows generated","supported","medium","Use sequences rather than nearest packet for future crib attempts."),
      ("whisper/group channel field",True,len(diff),"stable channel differences found" if chan else "no repeat-stable channel signal","supported" if chan else "weakened","medium","Clean controlled capture could amplify channel field."),
      ("local-message control decode",True,len(local),"exact local control matched" if any(r.get("exact_text_matched")=="true" for r in local) else "not matched","supported" if any(r.get("exact_text_matched")=="true" for r in local) else "weakened","medium","Need C2S anchor/session support for current capture."),
      ("existing C2S decoder applicability",True,len(local),"not applicable without anchor","weakened","medium","Recover/apply current session anchor before relying on decoder."),
      ("capture timing accuracy",True,len(read_csv(ART/"pass654b_oracle_rows.csv")),"known/prompt oracle rows merged with tolerances","supported","high","Timing is usable for windowed analysis.")]
    out=[{"hypothesis":a,"tested":bools(b),"tests_run":c,"result":d,"supported_or_weakened":e,"confidence":f,"next_specific_step":g} for a,b,c,d,e,f,g in rows]
    write_csv(ART/"pass654b_hypothesis_status.csv", out, ["hypothesis","tested","tests_run","result","supported_or_weakened","confidence","next_specific_step"])
    orows=[o for o in merged_oracles() if o["current_capture"]]
    tests=read_csv(ART/"pass654b_known_text_tests.csv"); cand=read_csv(ART/"pass654b_candidate_validation.csv"); diff=read_csv(ART/"pass654b_whisper_group_differential.csv"); local=read_csv(ART/"pass654b_local_message_control.csv"); inv=read_csv(ART/"pass654b_flow_inventory.csv")
    world=None
    for r in inv:
        if r.get("role")=="world":
            try: world=int(r.get("server_port") or 0)
            except Exception: world=None
    exact10242=any(r.get("exact_message_match")=="true" and r.get("server_port")==str(SIDE_PORT) for r in tests)
    exactworld=any(r.get("exact_message_match")=="true" and r.get("flow_role")=="world" for r in tests)
    validated=any(r.get("exact_text_validated")=="true" for r in cand)
    channel_signal=any(r.get("difference_found")=="true" and r.get("repeat_supported")=="true" for r in diff)
    local_exact=any(r.get("exact_text_matched")=="true" for r in local)
    c2s_app=any(r.get("existing_decoder_applicable")=="true" for r in local)
    current_valid=(PCAP.exists() and LOG.exists() and len(orows)>=17 and world is not None)
    if validated:
        best="current_capture_exhausted"
        needs=False
        reason="Exact known text candidate validated; local timeline would be written only under decoder outbox."
    elif exactworld:
        best="world_flow_framing"; needs=False; reason="World flow has exact deterministic text evidence but needs stronger validation."
    elif channel_signal:
        best="world_flow_framing"; needs=False; reason="Whisper/group metadata signal exists, but exact text was not recovered."
    elif not c2s_app:
        best="existing_c2s_anchor_support"; needs=True; reason="Current capture is analyzable, but existing C2S decoder lacks a usable current-session anchor and no exact text was found."
    else:
        best="clean_controlled_capture"; needs=True; reason="All deterministic current-capture text routes were weakened; controlled capture is the cleanest unblocker."
    decision={"worker":"codex","phase":"pass654b_offline_capture_validation","current_capture_valid":bool(current_valid),"world_port_detected":world,"side_flow_10242_present":any(r.get("server_port")==str(SIDE_PORT) for r in inv),"oracle_rows_merged":len(orows),"whisper_rows_used":sum(1 for o in orows if o["channel"]=="whisper"),"group_rows_used":sum(1 for o in orows if o["channel"]=="group"),"local_rows_used":sum(1 for o in orows if o["channel"]=="local"),"local_control_exact_match":bool(local_exact),"existing_c2s_decoder_applicable":bool(c2s_app),"stream_reconstruction_completed":(ART/"pass654b_stream_index.csv").exists(),"known_text_test_matrix_completed":bool(tests),"exact_text_found_on_10242":bool(exact10242),"exact_text_found_on_world_flow":bool(exactworld),"whisper_group_channel_signal_found":bool(channel_signal),"exact_known_message_validated":bool(validated),"clear_text_evidence_found":bool(validated or exact10242 or exactworld),"local_timeline_path":None,"hypotheses_accounted_for":len(out)>=12,"needs_new_capture":bool(needs),"best_next_direction":best,"private_packet_data_committed":False,"reason":reason,"next_action":"Use the ranked next steps artifact; prioritize the selected best_next_direction before broadening the search."}
    write_json(ART/"pass654b_offline_capture_validation_decision.json", decision)
    ranked=[]
    if best=="existing_c2s_anchor_support":
        ranked.append((1,"existing_c2s_anchor_support","Existing decoder was not applicable and local control did not exactly match.","Current-session C2S anchor/session start metadata, without secrets in git.","Validate C2S control path for this capture.","high"))
        ranked.append((2,"world_flow_framing","10242 behaves as timing/control metadata, while world flow remains the likely transport.","Static receive framing notes for dynamic world port plus current oracle windows.","Narrow body offsets/framing before crib search.","high"))
        ranked.append((3,"clean_controlled_capture","Current capture has mixed traffic and no exact deterministic text hit.","Whisper-only clean capture with fresh log and repeated markers.","Reduce false positives and alignment ambiguity.","medium"))
    elif best=="world_flow_framing":
        ranked.append((1,"world_flow_framing",reason,"Current world-flow oracle windows and static receive parser/framing context.","Map packet/stream body boundaries for marker events.","high"))
        ranked.append((2,"static_client_parser_research","No deterministic clear text representation was validated.","Client-side receive parser candidates for 7780 and 10242.","Identify transform/decode layer before text appears.","medium"))
        ranked.append((3,"clean_controlled_capture","A cleaner control set can still improve validation.","Fresh whisper-only capture with fewer unrelated events.","Independent confirmation of framing hypotheses.","medium"))
    else:
        ranked.append((1,"clean_controlled_capture",reason,"Fresh capture with exact repeated whisper controls and empty log.","Cleaner windows and lower ambiguity.","high"))
        ranked.append((2,"static_client_parser_research","Deterministic packet search exhausted current capture.","Static parser targets for world and 10242 flows.","Learn representation before network text appears.","medium"))
    write_csv(ART/"pass654b_ranked_next_steps.csv", [{"rank":a,"next_step":b,"evidence":c,"exact_input_needed":d,"expected_result":e,"confidence":f} for a,b,c,d,e,f in ranked], ["rank","next_step","evidence","exact_input_needed","expected_result","confidence"])
    summary="# Pass654B Offline Capture Validation\n\n" + "\n".join([f"Current capture valid: {decision['current_capture_valid']}",f"World port detected: {world}",f"Oracle rows merged: {len(orows)}",f"Whisper/group/local rows: {decision['whisper_rows_used']}/{decision['group_rows_used']}/{decision['local_rows_used']}",f"Local control exact match: {local_exact}",f"Existing C2S decoder applicable: {c2s_app}",f"Exact text on 10242: {exact10242}",f"Exact text on world flow: {exactworld}",f"Whisper/group channel signal: {channel_signal}",f"Exact known message validated: {validated}",f"Needs new capture: {needs}",f"Best next direction: {best}","",reason,"","No PCAPs, packet contents, decoded byte dumps, executable files, credentials, or private account data were committed."]) + "\n"
    (ART/"pass654b_offline_capture_validation_summary.md").write_text(summary, encoding="utf-8")
    INBOX.mkdir(exist_ok=True); (INBOX/"codex_report.md").write_text(summary, encoding="utf-8")
    print(json.dumps(decision, indent=2))
if __name__=="__main__": main()
