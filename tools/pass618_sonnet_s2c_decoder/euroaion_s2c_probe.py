"""
euroaion_s2c_probe.py
=====================
Phase 1: S2C packet inventory for EuroAion (Aion 4.x) world captures.
Phase 2: Bounded anchor candidate search.
Phase 3: Sequential rolling attempt.

All analysis is offline/static. No live process, no injection.

Findings:
- 163 S2C packets in the world TCP flow (port 7785).
- 28 small packets (<200 bytes); 135 are bulk data (1460 bytes).
- Chain rolling stays fully ambiguous (>50000 paths) due to:
  * Bulk data frames (1460B) accept all 256 k0 values via VM key roll.
  * No known S2C plaintext anchor available from static data alone.
- Blocker: S2C initial key is unknown. Cannot derive it from PCAP without
  either a plaintext oracle or the session-derived seed (from server handshake
  which is itself encrypted or missing).
"""

from __future__ import annotations

import csv
import struct
import sys
from pathlib import Path
from typing import Iterator

# ── re-use pass616 PCAP primitives ───────────────────────────────────────────
_PASS616 = Path(__file__).parent.parent / "pass616_sonnet_c2s_decoder"
sys.path.insert(0, str(_PASS616))

from euroaion_c2s_decoder import (
    STATIC_KEY, STD_AS, STD_BS, AION1_VA_LO, AION1_VA_HI,
    WORLD_PORT,
    _parse_pcapng, _extract_tcp, _flow_key, _direction,
    _ror32, decode_body, decode_opcode, complement_valid, key_from_hex,
    ANCHOR_FRAME,
)

# ── S2C constants ─────────────────────────────────────────────────────────────

# Seeds from prior session handshake analysis (used as negative control)
HANDSHAKE_SEEDS_HEX = [
    "191a7623",
    "2d66bd65",
    "3990c5a2",
    "735a1208",
]

# Previously believed S2C anchor (now confirmed INVALID)
CHECKPOINT_S2C_KEY = "4e99ca25a16c5487"


# ── packet extraction ─────────────────────────────────────────────────────────

def extract_s2c_packets(pcap_path: Path, anchor_frame: int = ANCHOR_FRAME) -> list[dict]:
    """Return all S2C packets in the same TCP flow as the C2S anchor."""
    all_rows: list[dict] = []
    for pkt_no, linktype, raw in _parse_pcapng(pcap_path):
        p = _extract_tcp(linktype, raw)
        if not p or not p["payload"]:
            continue
        fk = _flow_key(p)
        dir_ = _direction(p)
        all_rows.append({
            "packet_no": pkt_no,
            "flow":      fk,
            "direction": dir_,
            "payload":   p["payload"],
        })

    anchor = next((r for r in all_rows if r["packet_no"] == anchor_frame), None)
    if anchor is None:
        raise ValueError(f"Anchor C2S frame {anchor_frame} not found")
    anchor_flow = anchor["flow"]

    s2c = [
        r for r in all_rows
        if r["flow"] == anchor_flow
        and r["direction"] == "S2C"
        and len(r["payload"]) > 0
    ]
    return sorted(s2c, key=lambda r: r["packet_no"])


# ── inventory ─────────────────────────────────────────────────────────────────

def build_inventory(s2c_pkts: list[dict]) -> list[dict]:
    """Return high-level inventory rows (no raw hex)."""
    rows = []
    for idx, r in enumerate(s2c_pkts):
        plen = len(r["payload"])
        is_bulk = plen >= 1000
        rows.append({
            "index":       idx,
            "frame":       r["packet_no"],
            "payload_len": plen,
            "body_len":    plen - 2,
            "is_bulk":     "yes" if is_bulk else "no",
        })
    return rows


# ── anchor candidate search ───────────────────────────────────────────────────

def test_anchor_candidate(pkt: dict, key_hex: str, label: str) -> dict:
    """Test a single key candidate against a packet. Returns result dict."""
    body = pkt["payload"][2:]
    if len(body) < 3:
        return {"frame": pkt["packet_no"], "label": label, "valid_header": "no",
                "opcode_candidate": "n/a", "complement_ok": "no", "confidence": "none"}
    try:
        key = key_from_hex(key_hex)
        dec = decode_body(body, key)
        op = decode_opcode(dec[0])
        comp = complement_valid(dec)
        valid = op < 0x80 and comp
        conf = "high" if (op < 0x20 and comp) else ("medium" if (op < 0x80 and comp) else "none")
        return {
            "frame":           pkt["packet_no"],
            "label":           label,
            "valid_header":    "yes" if valid else "no",
            "opcode_candidate": f"0x{op:02X}",
            "complement_ok":   "yes" if comp else "no",
            "confidence":      conf,
        }
    except Exception as e:
        return {"frame": pkt["packet_no"], "label": label, "valid_header": "error",
                "opcode_candidate": "n/a", "complement_ok": "no", "confidence": "none",
                "note": str(e)}


def search_anchor_candidates(s2c_pkts: list[dict]) -> list[dict]:
    """
    Search for S2C anchor candidates among small packets using bounded seed tests.
    """
    results: list[dict] = []
    cid = 0

    small_pkts = [r for r in s2c_pkts if len(r["payload"]) < 200][:10]

    # Test 1: known checkpoint key (now confirmed invalid)
    for pkt in small_pkts[:3]:
        r = test_anchor_candidate(pkt, CHECKPOINT_S2C_KEY, "checkpoint_key_4e99")
        r["candidate_id"] = cid
        r["seed_or_key_source"] = "checkpoint_memory"
        r["header_rule_tested"] = "c2s_cipher_complement"
        r["reason"] = "Previously believed S2C anchor key"
        r["next_step"] = "n/a - confirmed invalid"
        results.append(r)
        cid += 1

    # Test 2: Brute k0 sweep on frame 4116 (shortest non-bulk S2C)
    tgt = next((r for r in small_pkts if r["packet_no"] == 4116), small_pkts[0])
    body = tgt["payload"][2:]
    hit_count = 0
    for k0 in range(256):
        if len(body) < 3: break
        dec0 = body[0] ^ k0
        dec2 = (~dec0) & 0xFF
        k1 = body[1] ^ STATIC_KEY[1] ^ 0x86 ^ body[0]
        k2 = body[2] ^ STATIC_KEY[2] ^ dec2 ^ body[1]
        for hi3 in [0x25, 0xC8]:
            cand_key = bytes([k0, k1, k2, hi3, 0xA1, 0x6C, 0x54, 0x87]).hex()
            r = test_anchor_candidate(tgt, cand_key, f"brute_k0_{k0:02X}_hi_{hi3:02X}")
            dec = decode_body(body, key_from_hex(cand_key))
            op = decode_opcode(dec[0])
            if op < 0x20 and complement_valid(dec):
                r["candidate_id"] = cid
                r["seed_or_key_source"] = "brute_k0_sweep"
                r["header_rule_tested"] = "c2s_cipher_complement_opcode_lt_0x20"
                r["reason"] = f"Single-frame valid low opcode 0x{op:02X}"
                r["next_step"] = "Need multi-frame chain to confirm"
                results.append(r)
                cid += 1
                hit_count += 1

    return results, hit_count


# ── rolling attempt ───────────────────────────────────────────────────────────

def attempt_s2c_rolling(s2c_pkts: list[dict], max_steps: int = 8) -> dict:
    """
    Attempt sequential S2C rolling. Documents the ambiguity explosion.
    Returns summary dict.
    """
    small_pkts = [r for r in s2c_pkts if len(r["payload"]) < 200]
    if not small_pkts:
        return {"status": "no_small_packets"}

    anchor_pkt = next((r for r in small_pkts if r["packet_no"] >= 4116), small_pkts[0])
    body_anchor = anchor_pkt["payload"][2:]

    # Seed all valid k0 values
    paths = []
    for k0 in range(256):
        if len(body_anchor) < 3: break
        dec0 = body_anchor[0] ^ k0
        dec2 = (~dec0) & 0xFF
        k1 = body_anchor[1] ^ STATIC_KEY[1] ^ 0x86 ^ body_anchor[0]
        k2 = body_anchor[2] ^ STATIC_KEY[2] ^ dec2 ^ body_anchor[1]
        for hi3 in [0x25, 0xC8]:
            key_try = bytearray([k0, k1, k2, hi3, 0xA1, 0x6C, 0x54, 0x87])
            dec = decode_body(body_anchor, key_try)
            op = decode_opcode(dec[0])
            if op < 0x80 and complement_valid(dec):
                paths.append((key_try, dec))

    # Use ALL S2C packets (including bulk) as the rolling target
    s2c_all = s2c_pkts
    start_idx = next((i for i, r in enumerate(s2c_all) if r["packet_no"] == anchor_pkt["packet_no"]), 0)

    trace = []
    first_dead = None
    for step in range(1, min(max_steps + 1, len(s2c_all) - start_idx)):
        pkt = s2c_all[start_idx + step]
        prev_pkt = s2c_all[start_idx + step - 1]
        body = pkt["payload"][2:]
        prev_body_len = len(prev_pkt["payload"]) - 2

        new_paths = []
        for cur_key, prev_dec in paths:
            prev_vas = []
            for i in range(min(len(prev_dec) - 3, 100)):
                prev_vas.append(struct.unpack_from('<I', prev_dec, i)[0])
            for k0 in range(256):
                if len(body) < 3: break
                dec0 = body[0] ^ k0
                dec2 = (~dec0) & 0xFF
                k1 = body[1] ^ STATIC_KEY[1] ^ 0x86 ^ body[0]
                k2 = body[2] ^ STATIC_KEY[2] ^ dec2 ^ body[1]
                cand = bytes([k0, k1, k2, cur_key[3], cur_key[4], cur_key[5], cur_key[6], cur_key[7]])
                val_prev = struct.unpack('<Q', cur_key)[0]
                val_cand = struct.unpack('<Q', cand)[0]
                delta = (val_cand - val_prev) & 0xFFFFFFFF
                tag = ""
                if delta == prev_body_len:
                    tag = "L"
                else:
                    for B in STD_BS:
                        if tag: break
                        for A in STD_AS:
                            if tag: break
                            inv_A = pow(A, -1, 2**32)
                            for shift in range(32):
                                rV = ((delta - B) * inv_A) & 0xFFFFFFFF
                                V = _ror32(rV, shift)
                                if V in prev_vas or (AION1_VA_LO <= V <= AION1_VA_HI):
                                    tag = "V"
                                    break
                if not tag: continue
                dec_cand = decode_body(body, bytearray(cand))
                op = decode_opcode(dec_cand[0])
                if op < 0x80 and complement_valid(dec_cand):
                    new_paths.append((bytearray(cand), dec_cand))
                    if len(new_paths) >= 50000: break
            if len(new_paths) >= 50000: break

        paths = new_paths
        trace.append({
            "step":    step,
            "frame":   pkt["packet_no"],
            "plen":    len(pkt["payload"]),
            "paths":   len(paths),
            "capped":  len(paths) >= 50000,
        })
        if not paths:
            first_dead = pkt["packet_no"]
            break

    return {
        "anchor_frame":      anchor_pkt["packet_no"],
        "trace":             trace,
        "first_dead_frame":  first_dead,
        "final_path_count":  len(paths),
        "ambiguous":         len(paths) > 1,
        "blocker":           (
            "S2C key-roll space stays maximally ambiguous through bulk data frames "
            "(1460-byte segments accept all k0 values via VM formula). "
            "Missing input: S2C initial key derived from server handshake."
            if len(paths) >= 50000 else
            ("No paths survive – S2C cipher formula may differ from C2S"
             if first_dead else "Converged")
        ),
    }
