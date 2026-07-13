#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ART = REPO / "artifacts"
REPORT = REPO / "inbox" / "codex_report.md"
PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in fields})


def main() -> int:
    candidates = read_csv(ART / "pass648_s2c_oracle_candidates.csv")
    pass647 = json.loads((ART / "pass647_dynamic_world_port_decision.json").read_text(encoding="utf-8")) if (ART / "pass647_dynamic_world_port_decision.json").exists() else {}
    validation = []
    for row in candidates:
        consistent = row.get("repeat_consistency") == "consistent"
        structural_score = int(row.get("structural_score") or 0)
        structural_ok = structural_score >= 60 and row.get("all_8_covered") == "true" and row.get("conflict_slots") == "0"
        validation.append({
            "candidate_id": row.get("candidate_id", ""),
            "validated_backward_packets": 0,
            "validated_forward_packets": 0,
            "repeat_markers_validated": str(consistent).lower(),
            "exact_marker_recovered": "false",
            "structural_checks_passed": str(structural_ok).lower(),
            "s2c_keyroll_validated": "false",
            "s2c_decoder_success": "false",
            "confidence": "medium_hypothesis" if structural_ok else "low_hypothesis",
            "reason": "candidate is crib-derived and not independently decoded/keyrolled; exact marker recovery not claimed",
        })
    fields = ["candidate_id","validated_backward_packets","validated_forward_packets","repeat_markers_validated","exact_marker_recovered","structural_checks_passed","s2c_keyroll_validated","s2c_decoder_success","confidence","reason"]
    write_csv(ART / "pass648_s2c_keyroll_validation.csv", validation, fields)

    all8 = [r for r in candidates if r.get("all_8_covered") == "true"]
    rep = [r for r in candidates if r.get("repeat_consistency") == "consistent"]
    literal_hits = 0
    literal_path = ART / "pass647_literal_text_hits_7780_10242.csv"
    if literal_path.exists():
        literal_hits = sum(1 for r in read_csv(literal_path) if r.get("server_port") == "7780")
    if not candidates:
        reason = "No bounded 7780 candidates survived zero-conflict all-slot crib tests; likely causes include S2C formula mismatch, unknown packet framing, or marker text carried primarily as structured/non-literal events."
    else:
        reason = "Bounded crib search produced slot-consistent hypotheses, but none has independent exact plaintext recovery or keyroll validation; decoder success is not claimed."
    if literal_hits == 0:
        reason += " Literal marker scan on 7780 found no ASCII/UTF-16LE marker text."
    decision = {
        "worker": "codex",
        "phase": "pass648_dynamic_world_7780_s2c_oracle",
        "fresh_broad_pcap_found": PCAP.exists(),
        "actual_world_port_used": pass647.get("actual_world_port_detected"),
        "dynamic_world_port_supported": True,
        "strong_marker_rows": pass647.get("strong_s2c_marker_rows", 0),
        "candidate_count": len(candidates),
        "all_8_slot_candidates": len(all8),
        "repeat_consistent_candidates": len(rep),
        "exact_marker_recovered": False,
        "s2c_keyroll_validated": False,
        "s2c_decoder_success": False,
        "needs_more_capture": len(rep) == 0 or literal_hits == 0,
        "raw_payload_committed": False,
        "raw_ciphertext_committed": False,
        "raw_plaintext_blob_committed": False,
        "packet_hashes_committed": False,
        "raw_binary_committed": False,
        "reason": reason,
        "next_action": "Collect a longer 7780 marker length ladder with repeated long markers, then rerun bounded keyroll validation using dynamic world-port selection.",
    }
    (ART / "pass648_s2c_oracle_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    summary = [
        "# Pass648 Dynamic World 7780 S2C Oracle Attempt",
        "",
        f"Fresh broad pcap found: {decision['fresh_broad_pcap_found']}",
        f"Actual world port used: {decision['actual_world_port_used']}",
        f"Strong marker rows: {decision['strong_marker_rows']}",
        f"Candidate count: {decision['candidate_count']}",
        f"All-8-slot candidates: {decision['all_8_slot_candidates']}",
        f"Repeat-consistent candidates: {decision['repeat_consistent_candidates']}",
        "Exact marker recovered: False",
        "S2C keyroll validated: False",
        "S2C decoder success: False",
        "",
        decision["reason"],
        "",
        "No raw payloads, ciphertext, plaintext blobs, packet hashes, binaries, DLLs, EXEs, keys, tokens, or secrets were written.",
    ]
    text = "\n".join(summary) + "\n"
    (ART / "pass648_s2c_oracle_summary.md").write_text(text, encoding="utf-8")
    REPORT.write_text(text, encoding="utf-8")
    print(json.dumps(decision, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
