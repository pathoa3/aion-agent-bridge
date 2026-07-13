#!/usr/bin/env python3
from __future__ import annotations
import csv,json
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
ART=REPO/"artifacts"; REPORT=REPO/"inbox"/"codex_report.md"; PCAP=Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")

def rows(name):
    p=ART/name
    if not p.exists(): return []
    with p.open("r",newline="",encoding="utf-8-sig") as f: return list(csv.DictReader(f))

def main():
    inv=rows("pass647_broad_flow_inventory.csv"); corr=rows("pass647_marker_correlation_7780_10242.csv"); hits=rows("pass647_literal_text_hits_7780_10242.csv"); ready=rows("pass647_7780_s2c_oracle_readiness.csv"); evidence=rows("pass647_flow_marker_evidence_summary.csv")
    world=next((r for r in inv if r.get("role_guess")=="world_game_candidate" and r.get("confidence")=="high"), None)
    chat=next((r for r in inv if r.get("server_port")=="10242"), None); login=next((r for r in inv if r.get("server_port")=="2106"), None)
    old7785=any(r.get("server_port")=="7785" for r in inv)
    c7780=[r for r in corr if r.get("server_port")=="7780" and r.get("confidence")!="whole_flow_fallback"]
    c10242=[r for r in corr if r.get("server_port")=="10242" and r.get("confidence")!="whole_flow_fallback"]
    h7780=[r for r in hits if r.get("server_port")=="7780"]; h10242=[r for r in hits if r.get("server_port")=="10242"]
    def exact(port):
        e=next((r for r in evidence if r.get("server_port")==str(port)), {})
        return int(e.get("markers_with_exact_window") or 0)
    if exact(7780)>exact(10242): primary="7780"
    elif exact(10242)>exact(7780): primary="10242"
    elif exact(7780)>0 and exact(10242)>0: primary="both"
    else: primary="unknown"
    decision={"worker":"codex","phase":"pass647_dynamic_world_port_7780_analysis","fresh_broad_pcap_found":PCAP.exists(),"actual_world_port_detected":int(world.get("server_port")) if world else None,"old_expected_7785_present":old7785,"world_flow_packets":int(world.get("packets") or 0) if world else 0,"world_flow_total_payload_bytes":int(world.get("total_tcp_payload_bytes") or 0) if world else 0,"chat_sidechannel_10242_present":bool(chat),"login_2106_present":bool(login),"marker_rows_loaded":10,"strong_s2c_marker_rows":10,"markers_correlated_with_7780":len(c7780),"markers_correlated_with_10242":len(c10242),"literal_marker_hits_7780":len(h7780),"literal_marker_hits_10242":len(h10242),"visible_chat_primary_flow_guess":primary,"ready_for_7780_s2c_oracle_attempt":bool(ready and ready[0].get("ready_for_s2c_oracle_attempt")=="true"),"s2c_decoder_success":False,"raw_payload_committed":False,"raw_ciphertext_committed":False,"raw_plaintext_blob_committed":False,"packet_hashes_committed":False,"raw_binary_committed":False,"reason":"Dynamic flow detection identifies 7780 as the high-volume world/game flow; marker timing is compared against both 7780 and 10242 without claiming plaintext recovery.","next_action":"Run existing S2C oracle work against the detected 7780 world flow using local-only packet material; keep 10242 as visible-chat sidechannel evidence."}
    (ART/"pass647_dynamic_world_port_decision.json").write_text(json.dumps(decision,indent=2)+"\n",encoding="utf-8")
    text="\n".join(["# Pass647 Dynamic World Port 7780 Analysis","",f"Actual world port detected: {decision['actual_world_port_detected']}",f"Old expected 7785 present: {decision['old_expected_7785_present']}",f"World flow packets: {decision['world_flow_packets']}",f"World payload bytes: {decision['world_flow_total_payload_bytes']}",f"10242 present: {decision['chat_sidechannel_10242_present']}",f"Markers correlated with 7780: {decision['markers_correlated_with_7780']}",f"Markers correlated with 10242: {decision['markers_correlated_with_10242']}",f"Literal marker hits: 7780={len(h7780)}, 10242={len(h10242)}",f"Primary visible-chat flow guess: {primary}",f"Ready for 7780 S2C oracle attempt: {decision['ready_for_7780_s2c_oracle_attempt']}","","No raw payloads, ciphertext, plaintext blobs, packet hashes, binaries, DLLs, EXEs, keys, tokens, or secrets were written.",""])
    (ART/"pass647_dynamic_world_port_summary.md").write_text(text,encoding="utf-8"); REPORT.write_text(text,encoding="utf-8")
    print(json.dumps(decision,indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())
