#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path
from pass651_common import *


def main() -> int:
    markers, old, _total = load_current_markers()
    freshness = read_csv(ART/"pass651_stage_a_freshness.csv")
    framing = read_csv(ART/"pass651_framing_hypotheses.csv")
    seq = read_csv(ART/"pass651_sequence_crib_candidates.csv")
    val = read_csv(ART/"pass651_sequence_crib_validation.csv")
    event = read_csv(ART/"pass651_10242_event_model.csv")
    triage = read_csv(ART/"pass651_local_payload_triage_summary.csv")
    high_framing = [r for r in framing if r.get("confidence")=="high"]
    repeat_seq = [r for r in seq if r.get("repeat_consistency")=="consistent"]
    exact = any(r.get("exact_marker_recovered")=="true" for r in val)
    event_supported = sum(1 for r in event if r.get("confidence") in ("high","medium")) >= max(1, len(event)//2)
    if repeat_seq:
        likely="stream_window"; best="stream_reassembly"; needs=False
    elif event_supported:
        likely="10242_event_model"; best="10242_event_model"; needs=False
    elif high_framing:
        likely="packet_sequence"; best="framing_static_analysis"; needs=True
    else:
        likely="compressed_or_encrypted"; best="local_payload_triage"; needs=True
    decision={"worker":"codex","phase":"pass651_extended_s2c_structure","current_capture_valid":len(markers)==8,"current_world_port":7780,"length_ladder_rows_used":len(markers),"stream_reassembly_done":(ART/"pass651_stream_marker_windows.csv").exists(),"framing_hypotheses_tested":len(framing),"sequence_crib_candidates":len(seq),"sequence_candidates_repeat_consistent":len(repeat_seq),"exact_marker_recovered":exact,"s2c_keyroll_validated":False,"s2c_decoder_success":False,"10242_event_model_supported":event_supported,"likely_marker_representation":likely,"best_next_direction":best,"needs_recapture":needs,"raw_payload_committed":False,"raw_ciphertext_committed":False,"raw_plaintext_blob_committed":False,"packet_hashes_committed":False,"derived_keys_committed":False,"reason":"Extended stages weakened nearest-packet text and simple length-signal hypotheses; sequence/window and 10242 event metadata are more useful than single-packet cribbing, with no exact marker recovery.","next_action":"If continuing current capture, prioritize stream/window framing analysis and 10242 event modeling; if recapturing, use cleaner whisper-only ladder with 5 repeats, 20-30s spacing, lengths 16/32/64/96, clear log, and filter host 51.83.147.97 with tcp port 2106 or 11000 or 10242 or tcp portrange 7770-7799."}
    write_json(ART/"pass651_extended_s2c_structure_decision.json", decision)
    summary=["# Pass651 Extended S2C Receive Structure", "", f"Current capture valid: {decision['current_capture_valid']}", f"Length ladder rows used: {len(markers)}", f"Framing hypotheses tested: {len(framing)}", f"Sequence crib candidates: {len(seq)}", f"Repeat-consistent sequence candidates: {len(repeat_seq)}", f"10242 event model supported: {event_supported}", f"Likely marker representation: {likely}", f"Best next direction: {best}", f"Needs recapture: {needs}", "", decision["reason"], "", "No raw payloads, ciphertext, plaintext blobs, packet hashes, derived keys, binaries, DLLs, EXEs, tokens, or secrets were written."]
    text="\n".join(summary)+"\n"
    (ART/"pass651_extended_s2c_structure_summary.md").write_text(text,encoding="utf-8")
    (REPO/"inbox"/"codex_report.md").write_text(text,encoding="utf-8")
    print(json.dumps(decision,indent=2))
    return 0
if __name__ == "__main__": raise SystemExit(main())
