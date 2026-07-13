"""
s2c_keyroll_validate.py
========================
Full autonomous S2C oracle runner: inventory + crib-drag + decode + keyroll validation.

This is the top-level script for pass636. It:
1. Parses the PCAP and builds the S2C packet inventory.
2. Runs the crib-drag oracle for all KXSEQ messages.
3. Decodes top candidates and validates.
4. If any S2C key is recovered, attempts stream rolling.
5. Writes all artifacts (metadata only, no raw bytes).
6. Produces the decision JSON.

Also implements Phase 5 fallback (non-chat known-plaintext scan for
world-entry packets like SM_VERSION/MOTD).
"""

from __future__ import annotations

import csv
import json
import struct
import sys
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

PCAP_PATH = Path(
    r"C:\AionTools\aion_decoder_agent\inbox\captures\startup_world_open_kxseq.pcapng"
)
ARTIFACTS = Path("artifacts")
TOOLS_DIR  = Path(__file__).parent

STATIC_KEY = b"nKO/WctQ0AVLbpzfBkS6NevDYT8ourG5CRlmdjyJ72aswx4EPq1UgZhFMXH?3iI9"
WORLD_PORT = 7785
CLIENT_IP  = "192.168.178.127"
SERVER_IP  = "54.37.197.248"

# Aion world-entry S2C: known fixed strings that appear in early packets
# These are tested as Phase 5 fallback if KXSEQ echo is not found.
MOTD_CANDIDATES = [
    ("SM_VERSION_prefix", b"\x00\x17"),          # opcode 0x17 = SM_VERSION in some versions
    ("welcome_string",    "Welcome".encode("utf-16-le")),
    ("version_3digit",    "4.6".encode("utf-16-le")),
    ("version_5digit",    "4.6.5".encode("utf-16-le")),
    ("version_nul",       "4.7".encode("utf-16-le")),
    ("EuroAion",          "EuroAion".encode("utf-16-le")),
    ("Aion",              "Aion".encode("utf-16-le")),
    ("server",            "server".encode("utf-16-le")),
    ("Server",            "Server".encode("utf-16-le")),
]

sys.path.insert(0, str(TOOLS_DIR))
from s2c_crib_drag_oracle import (
    _parse_pcapng, _extract_tcp, derive_key_from_crib, apply_key_from_slots,
    make_cribs, C2S_ORACLE, LABEL_TO_TEXT, BODY_OFFSETS,
    S2C_WINDOW_BEFORE, S2C_WINDOW_AFTER, run_oracle, key_slots_valid
)
from s2c_decode_from_oracle import (
    validate_decoded, brute_force_missing_slots, find_utf16le_strings,
    check_opcode_complement, is_plausible_utf16le
)


def load_pcap_packets(pcap_path: Path) -> tuple[list[dict], dict[int, dict]]:
    """Parse PCAP, return (all_world_pkts, pkt_by_frame)."""
    pkts = []
    for pkt_no, ts, lt, raw in _parse_pcapng(pcap_path):
        p = _extract_tcp(lt, raw)
        if not p or not p["payload"]:
            continue
        is_s2c = (p["src_ip"] == SERVER_IP and p["dst_ip"] == CLIENT_IP
                  and p["src_port"] == WORLD_PORT)
        is_c2s = (p["src_ip"] == CLIENT_IP and p["dst_ip"] == SERVER_IP
                  and p["dst_port"] == WORLD_PORT)
        if not (is_s2c or is_c2s):
            continue
        pkts.append({
            "frame":     pkt_no,
            "ts":        ts,
            "direction": "S2C" if is_s2c else "C2S",
            "payload":   p["payload"],
            "pay_len":   len(p["payload"]),
        })
    by_frame = {p["frame"]: p for p in pkts}
    return pkts, by_frame


def write_inventory(pkts: list[dict], path: Path) -> None:
    """Write S2C packet inventory CSV (no raw bytes)."""
    c2s_frames = {p["frame"] for p in pkts if p["direction"] == "C2S"}
    oracle_frames = {f for f, _, _ in C2S_ORACLE}

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["frame", "direction", "pay_len", "ts_relative",
                    "is_oracle_c2s", "oracle_label"])
        t0 = min(p["ts"] for p in pkts) if pkts else 0
        for p in pkts:
            label = ""
            if p["direction"] == "C2S" and p["frame"] in oracle_frames:
                label = next((lb for fr, lb, _ in C2S_ORACLE if fr == p["frame"]), "")
            w.writerow([
                p["frame"], p["direction"], p["pay_len"],
                f"{p['ts'] - t0:.3f}",
                p["frame"] in oracle_frames,
                label,
            ])
    print(f"[inventory] Written {len(pkts)} packets to {path}")


def run_phase5_motd(pkts: list[dict], by_frame: dict[int, dict]) -> list[dict]:
    """
    Phase 5: Try known world-entry strings on early S2C packets.
    Returns list of candidate rows.
    """
    print("[phase5] Testing MOTD/SM_VERSION cribs on early S2C packets ...")
    s2c_early = [p for p in pkts if p["direction"] == "S2C" and p["frame"] < 4200]
    candidates = []

    for name, crib in MOTD_CANDIDATES:
        if len(crib) < 4:
            continue
        for pkt in s2c_early:
            body = pkt["payload"][2:]
            for offset in BODY_OFFSETS:
                if offset + len(crib) > len(body):
                    break
                slots = derive_key_from_crib(body, offset, crib)
                valid, conflict = key_slots_valid(slots)
                if conflict > 0 or valid < 4:
                    continue
                candidates.append({
                    "phase":        5,
                    "crib_name":    name,
                    "s2c_frame":    pkt["frame"],
                    "body_offset":  offset,
                    "crib_len":     len(crib),
                    "valid_slots":  valid,
                    "conflict_slots": conflict,
                })

    print(f"[phase5] {len(candidates)} MOTD candidates")
    return candidates


def roll_key_forward(key8: list[int], body_len: int) -> list[int]:
    """Roll the 8-byte key forward by body_len (linear mode)."""
    val = struct.unpack("<Q", bytes(key8))[0]
    val = (val + body_len) & 0xFFFFFFFFFFFFFFFF
    return list(struct.pack("<Q", val))


def try_keyroll_validation(pkts: list[dict], by_frame: dict[int, dict],
                           seed_frame: int, seed_key8: list[int],
                           seed_label: str) -> dict:
    """
    Given a recovered 8-byte key at seed_frame, roll forward/backward
    and decode nearby S2C packets. Validate by looking for more KXSEQ echoes.
    """
    print(f"[keyroll] Seed frame {seed_frame} label={seed_label}")
    oracle_texts = {LABEL_TO_TEXT[lb] for _, lb, _ in C2S_ORACLE}

    # Get ordered S2C frames
    s2c_pkts = sorted([p for p in pkts if p["direction"] == "S2C"],
                      key=lambda x: x["frame"])

    seed_idx = next((i for i, p in enumerate(s2c_pkts)
                     if p["frame"] == seed_frame), None)
    if seed_idx is None:
        return {"validated": False, "reason": "seed frame not found in S2C list"}

    hits = 0
    checked = 0
    cur_key = list(seed_key8)

    # Roll forward
    for p in s2c_pkts[seed_idx + 1: seed_idx + 50]:
        body = p["payload"][2:]
        cur_key = roll_key_forward(cur_key, len(p["payload"]))  # try linear
        dec = apply_key_from_slots(body, {i: cur_key[i] for i in range(8)})
        if dec:
            checked += 1
            for text in oracle_texts:
                if text.encode("utf-16-le") in dec:
                    hits += 1
                    print(f"  [keyroll] Hit at frame {p['frame']}: {text}")

    return {
        "validated":   hits > 0,
        "hits":        hits,
        "checked":     checked,
        "seed_frame":  seed_frame,
        "seed_label":  seed_label,
    }


def main() -> dict:
    ARTIFACTS.mkdir(exist_ok=True)
    print("=" * 72)
    print("Pass636 S2C Known-Plaintext Oracle")
    print("=" * 72)

    # ── Verify PCAP ──────────────────────────────────────────────────────────
    if not PCAP_PATH.exists():
        print(f"[ERROR] PCAP not found: {PCAP_PATH}")
        return {"pcap_found": False, "terminal_condition": "pcap_missing"}

    print(f"[ok] PCAP: {PCAP_PATH.name} ({PCAP_PATH.stat().st_size:,} bytes)")

    # ── Phase 1: Inventory ───────────────────────────────────────────────────
    print("\n--- PHASE 1: S2C PACKET INVENTORY ---")
    pkts, by_frame = load_pcap_packets(PCAP_PATH)
    s2c_pkts = [p for p in pkts if p["direction"] == "S2C"]
    c2s_pkts = [p for p in pkts if p["direction"] == "C2S"]
    print(f"[inv] S2C: {len(s2c_pkts)}, C2S: {len(c2s_pkts)}, total: {len(pkts)}")
    inv_path = ARTIFACTS / "pass636_antigravity_s2c_packet_inventory.csv"
    write_inventory(pkts, inv_path)

    # ── Phase 2: Crib-drag oracle ─────────────────────────────────────────────
    print("\n--- PHASE 2: CRIB-DRAG ORACLE ---")
    crib_csv = ARTIFACTS / "pass636_antigravity_s2c_crib_candidates.csv"
    candidates = run_oracle(PCAP_PATH, crib_csv)

    # Summary stats
    total_crib_offsets = len(candidates)
    all_8_candidates   = [c for c in candidates if c["all_8_covered"]]
    labels_tested      = len({c["label"] for c in candidates})
    print(f"[crib] Total candidates: {total_crib_offsets}")
    print(f"[crib] All-8-key candidates: {len(all_8_candidates)}")
    print(f"[crib] Labels tested: {labels_tested}")

    if not candidates:
        print("[crib] No crib candidates found — KXSEQ echo not detected in S2C stream.")
        # Fall through to Phase 5

    # ── Phase 3: Decode top candidates ───────────────────────────────────────
    print("\n--- PHASE 3: DECODE TOP CANDIDATES ---")
    top_results   = []
    validations   = []
    s2c_success   = False
    best_frame    = None
    best_label    = None
    best_score    = 0
    recovered_key = None

    # Process top candidates (sorted by score)
    top_n = min(50, len(candidates))
    for row in candidates[:top_n]:
        frame       = row["s2c_frame"]
        label       = row["label"]
        body_offset = row["body_offset"]
        crib_var    = row["crib_variant"]
        text        = LABEL_TO_TEXT[label]

        pkt = by_frame.get(frame)
        if not pkt or pkt["pay_len"] < 3:
            continue
        body = pkt["payload"][2:]

        cribs = dict(make_cribs(text))
        crib  = cribs.get(crib_var)
        if not crib:
            continue

        slots = derive_key_from_crib(body, body_offset, crib)
        valid, conflict = key_slots_valid(slots)
        if conflict > 0:
            continue

        # Try to get full 8-slot key
        if valid < 8:
            full_slots = brute_force_missing_slots(body, slots, text)
        else:
            full_slots = dict(slots)

        key_recovered = (full_slots is not None and
                         all(full_slots.get(i, -1) >= 0 for i in range(8)))
        dec = apply_key_from_slots(body, full_slots) if key_recovered else None

        tr = {
            "s2c_frame":      frame,
            "label":          label,
            "body_offset":    body_offset,
            "crib_variant":   crib_var,
            "valid_slots":    valid,
            "key_recovered":  key_recovered,
            "text_found_exact": False,
            "validation_score": 0,
            "utf16_plausible": False,
            "comp_valid":     False,
            "opcode_xor":     None,
        }

        if dec:
            val = validate_decoded(dec, text, label)
            val["s2c_frame"]    = frame
            val["body_offset"]  = body_offset
            val["crib_variant"] = crib_var
            val["key_recovered"] = True

            tr["text_found_exact"]  = val["text_found_exact"]
            tr["validation_score"]  = val["validation_score"]
            tr["utf16_plausible"]   = val["utf16le_plausible"]
            tr["comp_valid"]        = val["comp_valid"]
            tr["opcode_xor"]        = val["opcode_xor_val"]

            validations.append(val)

            if val["validation_score"] > best_score:
                best_score = val["validation_score"]
                best_frame = frame
                best_label = label
                if val["text_found_exact"] and key_recovered:
                    recovered_key = [full_slots[i] for i in range(8)]

            if val["text_found_exact"]:
                s2c_success = True
                print(f"  [SUCCESS] frame={frame} label={label} offset={body_offset}"
                      f" score={val['validation_score']}")

        top_results.append(tr)

    # Write top candidates (metadata only)
    top_csv = ARTIFACTS / "pass636_antigravity_s2c_top_candidates.csv"
    with open(top_csv, "w", newline="", encoding="utf-8") as f:
        if top_results:
            writer = csv.DictWriter(f, fieldnames=list(top_results[0].keys()))
            writer.writeheader()
            writer.writerows(top_results)
        else:
            f.write("s2c_frame,label,body_offset,crib_variant,valid_slots,"
                    "key_recovered,text_found_exact,validation_score,"
                    "utf16_plausible,comp_valid,opcode_xor\n")
    print(f"[decode] Top candidates written: {top_csv}")

    # Write validation results (metadata only)
    val_csv = ARTIFACTS / "pass636_antigravity_s2c_validation.csv"
    with open(val_csv, "w", newline="", encoding="utf-8") as f:
        if validations:
            # Exclude raw decoded text — only keep safe metadata
            safe_fields = ["label", "s2c_frame", "body_offset", "crib_variant",
                           "decoded_len", "text_found_exact", "text_offset",
                           "utf16le_plausible", "comp_valid", "opcode_xor_val",
                           "len_word_found", "validation_score", "key_recovered"]
            writer = csv.DictWriter(f, fieldnames=safe_fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(validations)
        else:
            f.write("label,s2c_frame,body_offset,crib_variant,decoded_len,"
                    "text_found_exact,text_offset,utf16le_plausible,comp_valid,"
                    "opcode_xor_val,len_word_found,validation_score,key_recovered\n")
    print(f"[decode] Validation written: {val_csv}")

    # ── Phase 4: Keyroll validation ───────────────────────────────────────────
    keyroll_result = {}
    s2c_keyroll_validated = False
    if s2c_success and recovered_key:
        print("\n--- PHASE 4: S2C KEYROLL VALIDATION ---")
        keyroll_result = try_keyroll_validation(pkts, by_frame, best_frame,
                                                recovered_key, best_label)
        s2c_keyroll_validated = keyroll_result.get("validated", False)
        print(f"[keyroll] Result: {keyroll_result}")
    else:
        print("\n--- PHASE 4: SKIPPED (no S2C key recovered) ---")

    # ── Phase 5: MOTD/SM_VERSION fallback ────────────────────────────────────
    print("\n--- PHASE 5: MOTD/SM_VERSION FALLBACK ---")
    motd_candidates = run_phase5_motd(pkts, by_frame)

    # ── Build decoder status CSV ──────────────────────────────────────────────
    status = {
        "phase":                 636,
        "pcap_found":            True,
        "pcap_name":             PCAP_PATH.name,
        "s2c_packets_indexed":   len(s2c_pkts),
        "c2s_packets_indexed":   len(c2s_pkts),
        "crib_messages_tested":  labels_tested,
        "crib_offsets_tested":   len(BODY_OFFSETS),
        "consistent_candidates": total_crib_offsets,
        "all_8_candidates":      len(all_8_candidates),
        "top_decoded":           len(top_results),
        "keys_recovered":        sum(1 for r in top_results if r["key_recovered"]),
        "s2c_plaintext_recovered": s2c_success,
        "best_frame":            best_frame,
        "best_label":            best_label,
        "best_score":            best_score,
        "s2c_keyroll_validated": s2c_keyroll_validated,
        "motd_phase5_candidates": len(motd_candidates),
    }

    status_csv = ARTIFACTS / "pass636_antigravity_s2c_decoder_status.csv"
    with open(status_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["field", "value"])
        for k, v in status.items():
            writer.writerow([k, v])
    print(f"[status] Written: {status_csv}")

    # ── Determine terminal condition ──────────────────────────────────────────
    if s2c_success:
        terminal = "s2c_oracle_found"
        if s2c_keyroll_validated:
            terminal = "s2c_decoder_success"
    elif len(candidates) == 0 and len(motd_candidates) == 0:
        terminal = "existing_capture_insufficient"
    else:
        terminal = "existing_capture_insufficient"

    return {**status, "terminal_condition": terminal,
            "keyroll": keyroll_result,
            "motd_candidates": motd_candidates}


if __name__ == "__main__":
    result = main()
    print("\nFinal terminal condition:", result.get("terminal_condition"))
    print("S2C success:", result.get("s2c_plaintext_recovered"))
    print("Best frame:", result.get("best_frame"), "label:", result.get("best_label"))
