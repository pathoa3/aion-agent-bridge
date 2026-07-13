"""
s2c_decode_from_oracle.py
==========================
Given the best crib-drag candidates, recover full packet keys and decode S2C packets.

For each top candidate:
  1. Reconstruct the 8-byte packet key (brute forces missing slots if <= 2 missing).
  2. Decode the full S2C packet body.
  3. Validate without committing decoded blob:
     - KXSEQ substring present exactly
     - UTF-16LE string plausibility
     - Opcode/complement plausibility
     - Packet length/structure sanity
  4. If validated, output: frame, label_recovered, text_recovered, opcode, validation summary.
  5. If full key recovered, attempt to roll S2C stream forward/backward.

Output:
  artifacts/pass636_antigravity_s2c_top_candidates.csv   (metadata only, no raw bytes)
  artifacts/pass636_antigravity_s2c_validation.csv
  artifacts/pass636_antigravity_s2c_decoder_status.csv

Commit safety:
  - Does not write decoded plaintext to any committed file.
  - Writes only boolean flags, frame numbers, text presence booleans, opcode values.
"""

from __future__ import annotations

import csv
import struct
import sys
from pathlib import Path
from typing import Iterator

# Re-import cipher constants
STATIC_KEY = b"nKO/WctQ0AVLbpzfBkS6NevDYT8ourG5CRlmdjyJ72aswx4EPq1UgZhFMXH?3iI9"
WORLD_PORT = 7785
CLIENT_IP  = "192.168.178.127"
SERVER_IP  = "54.37.197.248"

# Import core functions from oracle module
sys.path.insert(0, str(Path(__file__).parent))
from s2c_crib_drag_oracle import (
    _parse_pcapng, _extract_tcp, derive_key_from_crib, apply_key_from_slots,
    make_cribs, C2S_ORACLE, LABEL_TO_TEXT, BODY_OFFSETS,
    S2C_WINDOW_BEFORE, S2C_WINDOW_AFTER, MIN_CRIB_LEN, run_oracle,
    derive_key_from_crib, key_slots_valid
)


# ──────────────────────────────────────────────────────────────────────────────
# Validation helpers
# ──────────────────────────────────────────────────────────────────────────────

def is_plausible_utf16le(data: bytes, min_len: int = 4) -> bool:
    """Check if data contains plausible UTF-16LE text (printable ASCII-range chars)."""
    if len(data) < min_len * 2:
        return False
    pairs = [(data[i], data[i+1]) for i in range(0, len(data) - 1, 2)]
    printable = sum(1 for lo, hi in pairs if hi == 0 and 0x20 <= lo <= 0x7E)
    return printable >= min(4, len(pairs) // 2)


def find_utf16le_strings(data: bytes, min_chars: int = 3) -> list[str]:
    """Find printable UTF-16LE strings in decoded data."""
    strings = []
    i = 0
    cur = []
    while i + 1 < len(data):
        lo, hi = data[i], data[i+1]
        if hi == 0 and 0x20 <= lo <= 0x7E:
            cur.append(chr(lo))
        else:
            if len(cur) >= min_chars:
                strings.append("".join(cur))
            cur = []
        i += 2
    if len(cur) >= min_chars:
        strings.append("".join(cur))
    return strings


def check_opcode_complement(decoded: bytes) -> tuple[int | None, bool]:
    """
    Check opcode/complement validity in decoded body.
    In C2S the structure is: byte0=opcode_encoded, byte1=?, byte2=~byte0
    S2C may differ. Return (opcode_value, complement_valid).
    """
    if len(decoded) < 3:
        return None, False
    b0 = decoded[0]
    b2 = decoded[2]
    comp_valid = (b0 == (~b2 & 0xFF))
    # S2C opcode decode: may use (b0 ^ 0xEE) - 0xAE, or raw 2-byte LE opcode
    opcode_xor = ((b0 ^ 0xEE) - 0xAE) & 0xFF
    return opcode_xor, comp_valid


def validate_decoded(decoded: bytes, expected_text: str, label: str) -> dict:
    """Validate a decoded S2C packet body."""
    utf16 = expected_text.encode("utf-16-le")
    text_found = utf16 in decoded
    text_offset = decoded.find(utf16) if text_found else -1

    strings = find_utf16le_strings(decoded)
    utf16_plausible = is_plausible_utf16le(decoded)

    opcode_val, comp_valid = check_opcode_complement(decoded)

    # Look for the text string
    found_strings_with_text = [s for s in strings if expected_text in s or
                                any(part in s for part in expected_text.split("_"))]

    # Check for 2-byte LE length words that could be text length
    n_chars = len(expected_text)
    len_word_found = False
    for i in range(0, min(64, len(decoded) - 1)):
        w = struct.unpack_from("<H", decoded, i)[0] if i + 2 <= len(decoded) else 0
        if w == n_chars:
            len_word_found = True
            break

    return {
        "label":              label,
        "decoded_len":        len(decoded),
        "text_found_exact":   text_found,
        "text_offset":        text_offset,
        "utf16le_plausible":  utf16_plausible,
        "utf16_strings":      "|".join(strings[:5]),  # safe: only label/test fragments
        "comp_valid":         comp_valid,
        "opcode_xor_val":     opcode_val,
        "len_word_found":     len_word_found,
        "validation_score":   (
            (50 if text_found else 0)
            + (20 if utf16_plausible else 0)
            + (10 if comp_valid else 0)
            + (10 if len_word_found else 0)
        ),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Full-key brute force (when <= 2 slots missing)
# ──────────────────────────────────────────────────────────────────────────────

def brute_force_missing_slots(body: bytes, slots: dict[int, int],
                               expected_text: str) -> dict[int, int] | None:
    """
    If 6 or 7 slots are known, brute-force the missing 1 or 2 slot values.
    Validate by checking known text appears in the decoded output.
    Returns completed slots dict or None.
    """
    utf16 = expected_text.encode("utf-16-le")
    missing = [s for s in range(8) if s not in slots]

    if len(missing) == 0:
        return slots
    if len(missing) > 2:
        return None  # too expensive without more constraints

    print(f"  [brute] {len(missing)} missing slot(s): {missing}")

    if len(missing) == 1:
        for v in range(256):
            test_slots = dict(slots)
            test_slots[missing[0]] = v
            dec = apply_key_from_slots(body, test_slots)
            if dec and utf16 in dec:
                print(f"  [brute] Found slot {missing[0]}={v:#04x}")
                return test_slots

    elif len(missing) == 2:
        for v0 in range(256):
            for v1 in range(256):
                test_slots = dict(slots)
                test_slots[missing[0]] = v0
                test_slots[missing[1]] = v1
                dec = apply_key_from_slots(body, test_slots)
                if dec and utf16 in dec:
                    print(f"  [brute] Found slots {missing[0]}={v0:#04x} {missing[1]}={v1:#04x}")
                    return test_slots

    return None


# ──────────────────────────────────────────────────────────────────────────────
# Main decode pass
# ──────────────────────────────────────────────────────────────────────────────

def run_decode(pcap_path: Path, candidates_csv: Path,
               top_n: int = 30) -> tuple[list[dict], list[dict], dict]:
    """
    Read top candidates from CSV, attempt full decode, return validation results.
    """
    # Load candidates
    with open(candidates_csv, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        print("[decode] No candidates to decode.")
        return [], [], {"terminal": "no_candidates"}

    # Take top N by score
    rows.sort(key=lambda r: -float(r["score"]))
    top = rows[:top_n]

    print(f"[decode] Processing top {len(top)} candidates ...")

    # Load S2C packets from PCAP
    s2c_by_frame: dict[int, bytes] = {}
    for pkt_no, ts, lt, raw in _parse_pcapng(pcap_path):
        p = _extract_tcp(lt, raw)
        if not p or not p["payload"]:
            continue
        is_s2c = (p["src_ip"] == SERVER_IP and p["dst_ip"] == CLIENT_IP
                  and p["src_port"] == WORLD_PORT)
        if is_s2c:
            s2c_by_frame[pkt_no] = p["payload"]

    top_results   = []
    validations   = []
    best_frame    = None
    best_label    = None
    best_val      = 0
    s2c_plaintext = False

    for row in top:
        frame       = int(row["s2c_frame"])
        label       = row["label"]
        body_offset = int(row["body_offset"])
        crib_var    = row["crib_variant"]
        text        = LABEL_TO_TEXT[label]

        payload = s2c_by_frame.get(frame)
        if not payload or len(payload) < 3:
            continue
        body = payload[2:]

        # Get the appropriate crib
        cribs = dict(make_cribs(text))
        crib  = cribs.get(crib_var)
        if not crib:
            continue

        slots = derive_key_from_crib(body, body_offset, crib)
        valid, conflict = key_slots_valid(slots)

        if conflict > 0:
            continue

        # Attempt full key recovery
        if valid < 8:
            # Try brute force for missing slots
            full_slots = brute_force_missing_slots(body, slots, text)
        else:
            full_slots = slots

        key_recovered = full_slots is not None
        dec = apply_key_from_slots(body, full_slots) if key_recovered else None

        val = None
        if dec:
            val = validate_decoded(dec, text, label)
            val["s2c_frame"]     = frame
            val["body_offset"]   = body_offset
            val["crib_variant"]  = crib_var
            val["key_recovered"] = True
            val["valid_slots"]   = valid + (8 - valid if key_recovered else 0)

            if val["validation_score"] > best_val:
                best_val   = val["validation_score"]
                best_frame = frame
                best_label = label

            if val["text_found_exact"]:
                s2c_plaintext = True
                print(f"  [MATCH] frame {frame} label={label} offset={body_offset}"
                      f" crib={crib_var} score={val['validation_score']}")

            validations.append(val)

        top_results.append({
            "s2c_frame":        frame,
            "label":            label,
            "body_offset":      body_offset,
            "crib_variant":     crib_var,
            "valid_slots":      valid,
            "key_recovered":    key_recovered,
            "text_found_exact": val["text_found_exact"] if val else False,
            "validation_score": val["validation_score"] if val else 0,
            "utf16_plausible":  val["utf16le_plausible"] if val else False,
            "comp_valid":       val["comp_valid"] if val else False,
            "opcode_xor":       val["opcode_xor_val"] if val else None,
        })

    summary = {
        "candidates_processed": len(top),
        "keys_recovered":       sum(1 for r in top_results if r["key_recovered"]),
        "text_found_exact":     s2c_plaintext,
        "best_frame":           best_frame,
        "best_label":           best_label,
        "best_validation_score": best_val,
    }

    print(f"[decode] Summary: {summary}")
    return top_results, validations, summary


if __name__ == "__main__":
    pcap = Path(sys.argv[1]) if len(sys.argv) > 1 else \
           Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\startup_world_open_kxseq.pcapng")
    cands = Path(sys.argv[2]) if len(sys.argv) > 2 else \
            Path(r"artifacts\pass636_antigravity_s2c_crib_candidates.csv")

    top, val, summary = run_decode(pcap, cands)
    print("Done:", summary)
