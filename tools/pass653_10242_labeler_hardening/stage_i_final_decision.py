#!/usr/bin/env python3
from pass653_common import *

def metric(path, name, default=""):
    for r in read_csv(path):
        if r.get("metric_name")==name: return r.get("value",default)
    return default

def bool_metric(path, name): return str(metric(path,name,"false")).lower()=="true"

def rate_risk(rate):
    try: r=float(rate)
    except Exception: return "unknown"
    if r<=0.25: return "low"
    if r<=0.5: return "medium"
    return "high"

def hint(v):
    try: x=float(v)
    except Exception: return "none"
    if x>=0.75: return "high"
    if x>=0.45: return "medium"
    if x>0: return "low"
    return "none"

def main():
    markers=load_markers()
    v2=read_csv(ART/"pass653_event_labeler_v2_known_markers.csv")
    high=sum(1 for r in v2 if r.get("confidence")=="high"); med=sum(1 for r in v2 if r.get("confidence")=="medium")
    fpr=metric(ART/"pass653_event_labeler_v2_metrics.csv","estimated_false_positive_rate","1")
    risk=rate_risk(fpr)
    acc="high" if high>=6 and risk in ("low","medium") else "medium" if high+med>=6 and risk!="high" else "low" if v2 else "none"
    rec=hint(metric(ART/"pass653_unsupervised_detector_metrics.csv","recall_hint","0")); prec=hint(metric(ART/"pass653_unsupervised_detector_metrics.csv","precision_hint","0"))
    cadence=read_csv(ART/"pass653_c2s22_cadence_model.csv"); role=cadence[0].get("model_name","unknown") if cadence else "unknown"
    clusters=read_csv(ART/"pass653_10242_s2c_batch_clusters.csv")
    cross=read_csv(ART/"pass653_cross_flow_timing.csv"); cross_add=sum(1 for r in cross if r.get("adds_confidence")=="true") >= max(1, len(cross)//3) if cross else False
    trans=read_csv(ART/"pass653_c2s22_transform_feasibility.csv"); text_found=any(int(r.get("hit_count") or 0)>0 and r.get("exact_text_recovered")=="true" for r in trans)
    kit=all((REPO/x).exists() for x in [Path("tools/pass653_10242_labeler_hardening/clean_capture_v2_start.ps1"),Path("tools/pass653_10242_labeler_hardening/clean_capture_v2_marker_commands.ps1"),Path("tools/pass653_10242_labeler_hardening/clean_capture_v2_stop_and_analyze.ps1")]) and (ART/"pass653_clean_capture_v2_runbook.md").exists()
    labelable=acc in ("medium","high") and risk in ("low","medium")
    needs_recapture=(risk=="high" or acc in ("none","low"))
    if risk=="high": best="run_clean_capture_v2"
    elif labelable: best="improve_event_labeler"
    elif role in ("heartbeat","poll"): best="return_to_7780_static_framing"
    else: best="run_clean_capture_v2"
    decision={"worker":"codex","phase":"pass653_10242_labeler_hardening","current_capture_valid":len(markers)==8,"chat_sidechannel_port":10242,"world_port":7780,"known_marker_rows":len(markers),"false_positive_baseline_done":(ART/"pass653_false_positive_baseline.csv").exists(),"event_labeler_v2_created":bool(v2),"event_labeler_v2_accuracy":acc,"event_labeler_v2_false_positive_risk":risk,"unsupervised_detector_created":(ART/"pass653_unsupervised_10242_events.csv").exists(),"unsupervised_detector_recall_hint":rec,"unsupervised_detector_precision_hint":prec,"c2s22_likely_role":role,"s2c_batch_clusters_found":len(clusters),"cross_flow_7780_adds_confidence":bool(cross_add),"c2s22_text_transform_found":bool(text_found),"visible_chat_extractable_from_10242_now":False,"visible_chat_event_labelable_from_10242_now":bool(labelable),"clean_capture_v2_kit_created":bool(kit),"needs_recapture":bool(needs_recapture),"best_next_direction":best,"s2c_decoder_success":False,"raw_payload_committed":False,"raw_ciphertext_committed":False,"raw_plaintext_blob_committed":False,"packet_hashes_committed":False,"derived_keys_committed":False,"reason":f"Event labeler v2 accuracy={acc}, false_positive_risk={risk}, unsupervised recall={rec}, precision={prec}, c2s22 role={role}.","next_action":"Run clean_capture_v2 if lower false positives are required; otherwise continue improving metadata event extraction on 10242."}
    write_json(ART/"pass653_10242_labeler_hardening_decision.json", decision)
    summary="# Pass653 10242 Labeler Hardening\n\n" + "\n".join([f"Known marker rows: {len(markers)}",f"Event labeler v2 accuracy: {acc}",f"False-positive risk: {risk}",f"Unsupervised recall hint: {rec}",f"Unsupervised precision hint: {prec}",f"C2S22 likely role: {role}",f"S2C batch clusters found: {len(clusters)}",f"Cross-flow 7780 adds confidence: {bool(cross_add)}",f"C2S22 text transform found: {bool(text_found)}",f"Visible chat event-labelable now: {bool(labelable)}",f"Needs recapture: {bool(needs_recapture)}",f"Best next direction: {best}","","No raw payloads, ciphertext, plaintext blobs, packet hashes, derived keys, binaries, DLLs, EXEs, tokens, or secrets were written."]) + "\n"
    (ART/"pass653_10242_labeler_hardening_summary.md").write_text(summary, encoding="utf-8")
    INBOX.mkdir(exist_ok=True)
    (INBOX/"codex_report.md").write_text(summary, encoding="utf-8")
    print(json.dumps(decision, indent=2))
if __name__=="__main__": main()
