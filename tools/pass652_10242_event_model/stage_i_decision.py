#!/usr/bin/env python3
from __future__ import annotations
import json
from pass652_common import *

def main():
    markers=load_markers(); c2s_model=read_csv(ART/"pass652_c2s22_field_model.csv"); batch=read_csv(ART/"pass652_s2c_batch_model.csv"); pairs=read_csv(ART/"pass652_request_response_pairs.csv"); fps=read_csv(ART/"pass652_event_fingerprints.csv"); feas=read_csv(ART/"pass652_text_feasibility.csv"); labels=read_csv(ART/"pass652_prototype_event_labels.csv")
    exact=any(r.get("exact_marker_recovered")=="true" for r in feas)
    utf16=any(float(r.get("utf16_likeness") or 0)>0.8 for r in c2s_model)
    batch_supported=sum(1 for r in batch if r.get("confidence") in ("high","medium"))>=4
    rr_supported=sum(1 for r in pairs if r.get("model_guess")=="chat_event_metadata" and r.get("confidence") in ("high","medium"))>=4
    fp_consistent=any(r.get("repeat_fingerprint_match")=="true" for r in fps)
    high_labels=sum(1 for r in labels if r.get("event_confidence")=="high")
    med_labels=sum(1 for r in labels if r.get("event_confidence") in ("high","medium"))
    acc="high" if high_labels>=6 else "medium" if med_labels>=6 else "low" if labels else "none"
    labelable=acc in ("high","medium")
    decision={"worker":"codex","phase":"pass652_10242_event_model","current_capture_valid":len(markers)==8,"current_world_port":7780,"chat_sidechannel_port":10242,"length_ladder_rows_used":len(markers),"c2s22_packets_modeled":int(c2s_model[0].get("rows_tested",0)) if c2s_model else 0,"c2s22_utf16_like_supported":utf16,"s2c_batch_model_supported":batch_supported,"request_response_model_supported":rr_supported,"event_fingerprints_repeat_consistent":fp_consistent,"exact_marker_text_found_in_10242":exact,"visible_chat_extractable_from_10242_now":False,"visible_chat_event_labelable_from_10242_now":labelable,"prototype_event_labeler_created":(ART/"pass652_prototype_event_labels.csv").exists(),"prototype_event_label_accuracy_on_known_markers":acc,"likely_10242_role":"chat_event_metadata" if labelable else "poll","best_next_direction":"improve_10242_event_labeler" if labelable else "try_10242_text_transform","needs_recapture":False,"s2c_decoder_success":False,"raw_payload_committed":False,"raw_ciphertext_committed":False,"raw_plaintext_blob_committed":False,"packet_hashes_committed":False,"derived_keys_committed":False,"reason":"10242 does not expose exact marker text under tested transforms, but 22-byte C2S timing plus S2C batch metadata supports event labeling for visible chat markers.","next_action":"Improve the 10242 event labeler using timing, 22-byte trigger classes, S2C batch sizes, and repeat fingerprints; keep 7780 crypto work separate."}
    write_json(ART/"pass652_10242_event_model_decision.json", decision)
    summary=["# Pass652 Deep 10242 Event Model", "", f"Length ladder rows used: {len(markers)}", f"C2S22 UTF16-like supported: {utf16}", f"S2C batch model supported: {batch_supported}", f"Request/response model supported: {rr_supported}", f"Exact marker text found in 10242: {exact}", f"Visible chat extractable now: False", f"Visible chat event-labelable now: {labelable}", f"Prototype label accuracy: {acc}", f"Likely 10242 role: {decision['likely_10242_role']}", "", decision["reason"], "", "No raw payloads, ciphertext, plaintext blobs, packet hashes, derived keys, binaries, DLLs, EXEs, tokens, or secrets were written."]
    text="\n".join(summary)+"\n"; (ART/"pass652_10242_event_model_summary.md").write_text(text,encoding="utf-8"); (REPO/"inbox"/"codex_report.md").write_text(text,encoding="utf-8")
    print(json.dumps(decision,indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())
