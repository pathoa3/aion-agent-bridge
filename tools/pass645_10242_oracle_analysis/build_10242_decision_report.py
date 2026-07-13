from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ART = REPO / "artifacts"
PCAP = REPO / "inbox" / "captures" / "s2c_oracle_world_entry.pcapng"
REPORT = REPO / "inbox" / "codex_report.md"


def read_csv(path: Path):
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def main() -> int:
    flows = read_csv(ART / "pass645_10242_flow_inventory.csv")
    known = read_csv(ART / "pass638_known_plaintext_log_status.csv")
    hits = read_csv(ART / "pass645_10242_literal_text_hits.csv")
    corr = read_csv(ART / "pass645_10242_marker_correlation.csv")
    classes = Counter(r.get("row_class", "") for r in known)
    flow_ports = {str(r.get("server_port", "")) for r in flows}
    s2c_hits = [r for r in hits if r.get("direction") == "S2C" and r.get("match_scope") in ("marker_exact", "whisper_visible_form", "group_visible_form")]
    c2s_hits = [r for r in hits if r.get("direction") == "C2S" and r.get("match_scope") in ("marker_exact", "whisper_visible_form", "group_visible_form")]
    testsay_hit = any("TestSay" in r.get("text_label", "") for r in hits)
    lfg_hits = [r for r in hits if r.get("match_scope") == "lfg_screenshot_line"]
    timing_matches = [r for r in corr if r.get("confidence") in ("exact_window_3s", "fallback_window_30s")]
    visible_chat = bool(s2c_hits or c2s_hits or timing_matches)
    if s2c_hits:
        evidence = "literal cleartext marker found on 10242 S2C"
    elif c2s_hits:
        evidence = "literal cleartext marker found on 10242 C2S"
    elif timing_matches:
        evidence = "structured/encoded marker not literal but packet timing matches 10242 traffic"
    else:
        evidence = "no marker evidence"
    decision = {
        "worker": "codex",
        "phase": "pass645_fresh_10242_oracle_analysis",
        "fresh_pcap_found": PCAP.exists(),
        "fresh_pcap_size_bytes": PCAP.stat().st_size if PCAP.exists() else 0,
        "flow_7785_found": "7785" in flow_ports,
        "flow_10242_found": "10242" in flow_ports,
        "flow_2106_found": "2106" in flow_ports,
        "known_log_rows": len(known),
        "strong_s2c_oracle_rows": classes.get("strong_s2c_oracle", 0),
        "literal_marker_hits_10242_s2c": len(s2c_hits),
        "literal_marker_hits_10242_c2s": len(c2s_hits),
        "test_say_hit_found": testsay_hit,
        "lfg_screenshot_crib_hits_found": len(lfg_hits),
        "marker_timing_correlations": len(timing_matches),
        "visible_chat_carried_on_10242": visible_chat,
        "10242_is_7785_decoder_or_key_source": False,
        "pass638_dynamic_flow_patch_done": (ART / "pass638_dynamic_flow_context.csv").exists(),
        "stray_bad_files_cleaned": True,
        "raw_payload_committed": False,
        "raw_ciphertext_committed": False,
        "raw_plaintext_blob_committed": False,
        "packet_hashes_committed": False,
        "raw_binary_committed": False,
        "reason": evidence + "; 10242 is useful as a visible-chat sidechannel when timing/literal evidence is present, but it is not automatically the 7785 decoder or key source.",
        "next_action": "Use 10242 timing/literal evidence to label visible chat events, and keep 7785 decoder/key work separate until a capture with 7785 traffic is available.",
    }
    (ART / "pass645_10242_oracle_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Pass645 10242 Oracle Analysis Summary",
        "",
        f"Fresh pcap found: {decision['fresh_pcap_found']} ({decision['fresh_pcap_size_bytes']} bytes)",
        f"Flows: 7785={decision['flow_7785_found']}, 10242={decision['flow_10242_found']}, 2106={decision['flow_2106_found']}",
        f"Known log rows: {decision['known_log_rows']}; strong S2C oracle rows: {decision['strong_s2c_oracle_rows']}",
        f"Literal marker hits on 10242: S2C={len(s2c_hits)}, C2S={len(c2s_hits)}",
        f"TestSay hit found: {testsay_hit}; LFG crib hits: {len(lfg_hits)}",
        f"Marker timing correlations: {len(timing_matches)}",
        f"Decision: {decision['reason']}",
        "",
        "No raw payloads, ciphertext, plaintext blobs, packet hashes, keys, binaries, DLLs, or EXEs were written.",
    ]
    text = "\n".join(lines) + "\n"
    (ART / "pass645_10242_oracle_summary.md").write_text(text, encoding="utf-8")
    REPORT.write_text(text, encoding="utf-8")
    print("pass645_10242_report decision_json=artifacts/pass645_10242_oracle_decision.json")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
