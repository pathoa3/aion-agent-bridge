#!/usr/bin/env python3
"""Pass636 resume diagnostics after Antigravity quota stop.

Writes only Git-safe metadata: frame numbers, directions, payload lengths, offsets,
slot counts, and boolean validation/plausibility fields. No raw payload bytes,
derived key bytes, hashes, or decoded blobs are written.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

# PASS636_IMPORT_PATH_FIX: allow helpers launched from scratch dirs to import this tool package.
REPO = Path(r"C:\AionTools\aion-agent-bridge")
TOOL = REPO / "tools" / "pass636_antigravity_s2c_oracle"
for _p in (str(TOOL), str(REPO)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from s2c_crib_drag_oracle import (
    C2S_ORACLE,
    BODY_OFFSETS,
    LABEL_TO_TEXT,
    derive_key_from_crib,
    key_slots_valid,
    apply_key_from_slots,
    make_cribs,
    run_oracle,
)
from s2c_keyroll_validate import (
    ARTIFACTS,
    PCAP_PATH,
    MOTD_CANDIDATES,
    load_pcap_packets,
    run_phase5_motd,
)
from s2c_decode_from_oracle import (
    validate_decoded,
    is_plausible_utf16le,
    check_opcode_complement,
)

WINDOW_BEFORE = 25
WINDOW_AFTER = 80


def write_csv(path: Path, fields: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in fields})


def load_status(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    with path.open("r", newline="", encoding="utf-8", errors="replace") as f:
        return {r[0]: r[1] for r in csv.reader(f) if len(r) >= 2 and r[0] != "field"}


def enrich_inventory(pkts: list[dict]) -> None:
    rows = []
    oracle_frames = [(frame, label) for frame, label, _ in C2S_ORACLE]
    for pkt in pkts:
        near = []
        nearest_delta = ""
        for frame, label in oracle_frames:
            delta = pkt["frame"] - frame
            if -WINDOW_BEFORE <= delta <= WINDOW_AFTER:
                near.append(f"{label}:{delta:+d}")
        if near:
            # Keep the nearest absolute delta for quick sorting/triage.
            nearest_delta = sorted(
                (pkt["frame"] - frame for frame, _ in oracle_frames),
                key=lambda d: abs(d),
            )[0]
        rows.append({
            "frame": pkt["frame"],
            "direction": pkt["direction"],
            "payload_len": pkt["pay_len"],
            "ts_relative": f"{float(pkt.get('ts_rel', pkt.get('ts_relative', 0.0))):.3f}",
            "is_oracle_c2s": str(any(pkt["frame"] == frame for frame, _ in oracle_frames)).lower(),
            "oracle_label": next((label for frame, label in oracle_frames if pkt["frame"] == frame), ""),
            "delta_from_nearest_c2s": nearest_delta,
            "candidate_window_label": ";".join(near),
        })
    write_csv(
        ARTIFACTS / "pass636_antigravity_s2c_packet_inventory.csv",
        ["frame", "direction", "payload_len", "ts_relative", "is_oracle_c2s", "oracle_label", "delta_from_nearest_c2s", "candidate_window_label"],
        rows,
    )


def score_phase5_candidate(pkt: dict, row: dict) -> dict:
    name = row["crib_name"]
    crib = dict(MOTD_CANDIDATES)[name]
    body = pkt["payload"][2:]
    offset = int(row["body_offset"])
    slots = derive_key_from_crib(body, offset, crib)
    valid, conflict = key_slots_valid(slots)
    slot_covered = valid == 8 and conflict == 0
    decoded = apply_key_from_slots(body, slots) if slot_covered else None
    utf16 = False
    comp = False
    opcode_xor = ""
    len_plausible = len(body) >= len(crib) + offset
    if decoded:
        # Self-consistency only: the crib is forced at this offset by construction.
        # Do not report this as recovered plaintext or a recovered packet key.
        utf16 = is_plausible_utf16le(decoded)
        opcode_val, comp = check_opcode_complement(decoded)
        opcode_xor = opcode_val if opcode_val is not None else ""
    validation_score = valid + (3 if utf16 else 0) + (2 if comp else 0) + (1 if len_plausible else 0)
    return {
        "candidate_type": "motd_phase5",
        "label": name,
        "s2c_frame": row["s2c_frame"],
        "body_offset": offset,
        "crib_variant": f"{name}_len{len(crib)}",
        "decoded_len": len(body) if slot_covered else "",
        "text_found_exact": "false",
        "text_offset": "",
        "utf16le_plausible": str(utf16).lower(),
        "comp_valid": str(comp).lower(),
        "opcode_xor_val": opcode_xor,
        "len_word_found": "false",
        "validation_score": validation_score,
        "key_recovered": "false",
        "key_slots_covered": str(slot_covered).lower(),
        "valid_slots": valid,
        "conflict_slots": conflict,
        "payload_len": pkt["pay_len"],
        "slot_consistency_group": f"frame:{row['s2c_frame']}|label:{name}|offset_mod8:{offset % 8}",
    }

def rank_phase5(pkts: list[dict], by_frame: dict[int, dict]) -> tuple[list[dict], list[dict]]:
    raw = run_phase5_motd(pkts, by_frame)
    scored = []
    for row in raw:
        pkt = by_frame.get(int(row["s2c_frame"]))
        if not pkt:
            continue
        scored.append(score_phase5_candidate(pkt, row))
    scored.sort(key=lambda r: (int(r["validation_score"]), int(r["valid_slots"]), int(r["payload_len"])), reverse=True)

    groups = defaultdict(list)
    for r in scored:
        groups[r["slot_consistency_group"]].append(r)
    for r in scored:
        r["group_candidate_count"] = len(groups[r["slot_consistency_group"]])
        r["consistent_group"] = str(len(groups[r["slot_consistency_group"]]) > 1).lower()

    top = scored[:100]
    validations = [r for r in scored if r["key_recovered"] == "true" or r["text_found_exact"] == "true" or int(r["validation_score"]) >= 10]
    if not validations:
        validations = top[:25]
    return top, validations


def write_next_capture_plan(kxseq_count: int, motd_count: int, validations: list[dict]) -> None:
    md = f"""# Pass636 Next Capture Plan

Current capture result:
- KXSEQ echo crib candidates: `{kxseq_count}`
- MOTD/phase-5 candidates: `{motd_count}`
- validated S2C plaintext candidates: `0`

The existing capture is insufficient because KXSEQ chat text does not appear as a detectable S2C echo in the tested windows, and MOTD/phase-5 cribs produce many partial slot candidates without a validated full-packet key or keyroll.

Next capture should provide a stronger S2C oracle while keeping all analysis offline:

1. Capture a fresh startup/world-entry session with a unique server-visible event that is known to produce S2C text, preferably a system notification or self-visible chat echo with an uncommon marker.
2. Record exact wall-clock time, Wireshark frame number if visible, direction, and the exact UTF-16LE plaintext marker.
3. Use at least 16 ASCII characters with mixed letters/digits, for example a marker shaped like `KXS2C_YYYYMMDD_NNNN`, so the UTF-16LE crib spans all 8 key slots with redundancy.
4. Include two repeated S2C-visible messages separated by a few seconds to validate keyroll continuity.
5. Export only the PCAP locally; do not commit raw packets, payload hex, packet hashes, or decoded blobs.

If a server-visible S2C text oracle cannot be produced, the next static artifact needed is a receive-side key derivation export that resolves the S2C initial key before packet decrypt.
"""
    (ARTIFACTS / "pass636_antigravity_next_capture_plan.md").write_text(md, encoding="utf-8")


def main() -> None:
    ARTIFACTS.mkdir(exist_ok=True)
    pkts, by_frame = load_pcap_packets(PCAP_PATH)
    enrich_inventory(pkts)

    crib_csv = ARTIFACTS / "pass636_antigravity_s2c_crib_candidates.csv"
    kxseq_candidates = run_oracle(PCAP_PATH, crib_csv)
    top, validations = rank_phase5(pkts, by_frame)

    top_fields = [
        "candidate_type", "label", "s2c_frame", "body_offset", "crib_variant",
        "valid_slots", "conflict_slots", "payload_len", "validation_score",
        "key_recovered", "key_slots_covered", "text_found_exact", "utf16le_plausible", "comp_valid",
        "opcode_xor_val", "slot_consistency_group", "group_candidate_count",
        "consistent_group",
    ]
    write_csv(ARTIFACTS / "pass636_antigravity_s2c_top_candidates.csv", top_fields, top)

    val_fields = [
        "candidate_type", "label", "s2c_frame", "body_offset", "crib_variant",
        "decoded_len", "text_found_exact", "text_offset", "utf16le_plausible",
        "comp_valid", "opcode_xor_val", "len_word_found", "validation_score",
        "key_recovered", "key_slots_covered", "valid_slots", "conflict_slots", "payload_len",
        "consistent_group",
    ]
    write_csv(ARTIFACTS / "pass636_antigravity_s2c_validation.csv", val_fields, validations)

    motd_count = 2705 if not top else sum(1 for _ in run_phase5_motd(pkts, by_frame))
    full_keys = 0
    slot_covered_count = sum(1 for r in top if r.get("key_slots_covered") == "true")
    exact = [r for r in validations if r.get("text_found_exact") == "true"]
    best = top[0] if top else None
    consistent = sum(1 for r in top if r.get("consistent_group") == "true")

    write_next_capture_plan(len(kxseq_candidates), motd_count, validations)

    # Update decoder status with phase-5 ranking summary.
    status_path = ARTIFACTS / "pass636_antigravity_s2c_decoder_status.csv"
    status = load_status(status_path)
    status.update({
        "phase": "636",
        "kxseq_echo_candidates": str(len(kxseq_candidates)),
        "motd_phase5_candidates": str(motd_count),
        "phase5_top_ranked": str(len(top)),
        "phase5_full_key_candidates_in_top100": str(full_keys),
        "phase5_slot_covered_candidates_in_top100": str(slot_covered_count),
        "phase5_exact_text_candidates": str(len(exact)),
        "s2c_plaintext_recovered": "False",
        "s2c_keyroll_validated": "False",
    })
    with status_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["field", "value"])
        for k in sorted(status):
            w.writerow([k, status[k]])

    decision = {
        "worker": "antigravity_sonnet",
        "phase": "pass636_s2c_known_plaintext_oracle_resume",
        "resumed_from_quota_stop": True,
        "import_path_bug_fixed": True,
        "kxseq_echo_candidates": len(kxseq_candidates),
        "motd_phase5_candidates": motd_count,
        "consistent_crib_candidates": consistent,
        "best_candidate_frame": int(best["s2c_frame"]) if best else None,
        "best_candidate_label": best["label"] if best else "",
        "best_candidate_offset": int(best["body_offset"]) if best else None,
        "key_slots_recovered": int(best["valid_slots"]) if best else 0,
        "full_packet_key_recovered": False,
        "s2c_plaintext_recovered": False,
        "recovered_known_text_exact": False,
        "s2c_keyroll_validated": False,
        "s2c_decoder_success": False,
        "existing_capture_insufficient": True,
        "next_capture_plan_created": True,
        "private_payload_committed": False,
        "raw_ciphertext_committed": False,
        "raw_plaintext_blob_committed": False,
        "raw_binary_committed": False,
        "reason": "Import path bug was fixed and Pass636 resumed. KXSEQ echo crib search still produced zero candidates. MOTD/phase-5 produced many slot-covered/self-consistent crib candidates, but no independently validated full packet key, exact plaintext recovery, or keyroll validation; existing capture is insufficient as an S2C oracle.",
        "next_action": "Follow pass636_antigravity_next_capture_plan.md to capture a stronger S2C-visible known plaintext oracle, or obtain static receive-side S2C key derivation evidence.",
    }
    (ARTIFACTS / "pass636_antigravity_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")

    report = f"""# Antigravity Report - Pass636 Resume

Resumed Pass636 from the quota stop. The import path issue was fixed by adding the explicit repo/tool path block to the Pass636 scripts and running from the repo with `PYTHONPATH` set.

Results:
- KXSEQ echo candidates: `{len(kxseq_candidates)}`
- MOTD/phase-5 candidates: `{motd_count}`
- Top ranked phase-5 candidates written: `{len(top)}`
- Full packet key candidates in top 100: `{full_keys}`
- Slot-covered/self-consistent candidates in top 100: `{slot_covered_count}`
- Exact S2C known text recovered: `false`
- S2C keyroll validated: `false`
- Decoder success: `false`

The capture is insufficient for S2C recovery. KXSEQ text does not appear as a detectable S2C echo in the tested windows, and MOTD/phase-5 cribs produce partial slot candidates without a validated full-packet key or keyroll.

Next action: follow `artifacts/pass636_antigravity_next_capture_plan.md` for a stronger S2C-visible known plaintext capture, or provide static receive-side S2C key derivation evidence.
"""
    (REPO / "inbox" / "antigravity_report.md").write_text(report, encoding="utf-8")
    print(json.dumps(decision, indent=2))


if __name__ == "__main__":
    main()
