"""
s2c_crib_drag_oracle.py
========================
S2C known-plaintext (crib-drag) oracle for EuroAion Aion 4.x world connections.

Cipher model (same as C2S, verified from pass616 decoder):
  out[0] = in[0] ^ key[0]
  out[i] = in[i] ^ STATIC_KEY[i & 63] ^ key[i & 7] ^ in[i-1]   for i >= 1

Therefore for known plaintext P at body offset O in ciphertext C (body starting after 2-byte header):
  key[(O)   & 7] = C[O]   ^ P[0]                                          (i=0)
  key[(O+j) & 7] = C[O+j] ^ P[j] ^ STATIC_KEY[(O+j) & 63] ^ C[O+j-1]    (j>0)

We can recover all 8 key bytes if the crib is >= 8 bytes and hits all 8 mod-8 offsets.

S2C chat echo structure (Aion /say broadcast SM_SHOW_NOTIFICATION or SM_CHAT):
  The server echoes chat to all players. The S2C chat packet body (decoded) typically contains:
    [opcode_lo] [opcode_hi] [complement_lo] [complement_hi] [channel] [unk] [charname_len] ...
    [charname in UTF-16LE] [NUL] [msg_len] [message in UTF-16LE] [NUL]

  But since we don't know the S2C opcode or structure, we crib-drag on the known text
  string in UTF-16LE at various body offsets, without assuming structure.

Crib variants for KXSEQ_001 (text = "KXSEQ_001"):
  - raw UTF-16LE: b'K\x00X\x00S\x00E\x00Q\x00_\x000\x000\x001\x00'
  - with NUL terminator
  - with 2-byte prefix (length word)
  etc.

This script:
  1. Parses the PCAP and indexes all S2C packets.
  2. For each KXSEQ message, encodes all crib variants.
  3. For each S2C packet in a window around the matching C2S frame, at each body offset:
     - Derives provisional key bytes.
     - Scores by: consistency, key plausibility, key byte count recovered.
  4. Outputs ranked candidates as CSV (no raw ciphertext or derived keys).

Usage:
  python s2c_crib_drag_oracle.py [pcap_path] [out_csv]
"""

from __future__ import annotations

import csv
import struct
import sys
from pathlib import Path
from typing import Iterator

# ──────────────────────────────────────────────────────────────────────────────
# Constants (from verified C2S decoder pass616)
# ──────────────────────────────────────────────────────────────────────────────
STATIC_KEY = b"nKO/WctQ0AVLbpzfBkS6NevDYT8ourG5CRlmdjyJ72aswx4EPq1UgZhFMXH?3iI9"
WORLD_PORT = 7785
CLIENT_IP  = "192.168.178.127"
SERVER_IP  = "54.37.197.248"

# Known C2S oracle frames and messages
C2S_ORACLE = [
    (4329, "KXSEQ_001",                "K X S E Q _ 0 0 1"),
    (4353, "KXSEQ_002_A",              "K X S E Q _ 0 0 2 _ A"),
    (4360, "KXSEQ_003_AA",             "K X S E Q _ 0 0 3 _ A A"),
    (4389, "KXSEQ_004_AAA",            "K X S E Q _ 0 0 4 _ A A A"),
    (4399, "KXSEQ_005_AAAA",           "K X S E Q _ 0 0 5 _ A A A A"),
    (4402, "KXSEQ_006_AAAAAAAA",       "K X S E Q _ 0 0 6 _ A A A A A A A A"),
    (4412, "KXSEQ_007_AAAAAAAAAAAAAAAA","K X S E Q _ 0 0 7 _ A A A A A A A A A A A A A A A A"),
    (4417, "KXSEQ_008_0123456789",     "K X S E Q _ 0 0 8 _ 0 1 2 3 4 5 6 7 8 9"),
    (4422, "KXSEQ_009_ABABABABABABABAB","K X S E Q _ 0 0 9 _ A B A B A B A B A B A B A B A B"),
    (4429, "KXSEQ_010_REPEAT",         "K X S E Q _ 0 1 0 _ R E P E A T"),
    (4435, "KXSEQ_010_REPEAT",         "K X S E Q _ 0 1 0 _ R E P E A T"),
]

# Map label -> plain ASCII text
LABEL_TO_TEXT = {
    "KXSEQ_001":                "KXSEQ_001",
    "KXSEQ_002_A":              "KXSEQ_002_A",
    "KXSEQ_003_AA":             "KXSEQ_003_AA",
    "KXSEQ_004_AAA":            "KXSEQ_004_AAA",
    "KXSEQ_005_AAAA":           "KXSEQ_005_AAAA",
    "KXSEQ_006_AAAAAAAA":       "KXSEQ_006_AAAAAAAA",
    "KXSEQ_007_AAAAAAAAAAAAAAAA":"KXSEQ_007_AAAAAAAAAAAAAAAA",
    "KXSEQ_008_0123456789":     "KXSEQ_008_0123456789",
    "KXSEQ_009_ABABABABABABABAB":"KXSEQ_009_ABABABABABABABAB",
    "KXSEQ_010_REPEAT":         "KXSEQ_010_REPEAT",
}

# Body offsets to try (relative to start of body = after 2-byte masked length header)
BODY_OFFSETS = [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32]

# S2C window around each C2S frame (look at frames in [c2s_frame - 5, c2s_frame + 120])
S2C_WINDOW_BEFORE = 5
S2C_WINDOW_AFTER  = 120

# Minimum crib length to bother with (too short = too many false positives)
MIN_CRIB_LEN = 8

# Key byte plausibility filter: key bytes from 0x00-0xFF all valid, but all-zero or
# all-same key is suspicious (score penalty). No filter needed, just scoring.


# ──────────────────────────────────────────────────────────────────────────────
# PCAP parser (reused from pass616 with timestamps added)
# ──────────────────────────────────────────────────────────────────────────────

def _parse_pcapng(path: Path) -> Iterator[tuple[int, float, int, bytes]]:
    """Yield (packet_no, timestamp_s, linktype, raw_packet_bytes)."""
    data   = path.read_bytes()
    off    = 0
    endian = "<"
    ifaces: dict[int, tuple[int, int]] = {}  # iid -> (linktype, tsresol)
    iface_idx = 0
    pkt_no    = 0

    while off + 12 <= len(data):
        btype, blen = struct.unpack_from(endian + "II", data, off)
        if blen < 12 or off + blen > len(data):
            break
        body_off = off + 8

        if btype == 0x0A0D0D0A:
            bom = struct.unpack_from("<I", data, off + 8)[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
        elif btype == 1:  # IDB
            lt = struct.unpack_from(endian + "H", data, body_off)[0]
            tsresol = 6  # default microseconds
            ifaces[iface_idx] = (lt, tsresol)
            iface_idx += 1
        elif btype == 6:  # EPB
            iid, tsh, tsl, cap_len, _ = struct.unpack_from(endian + "IIIII", data, body_off)
            ts_raw = (tsh << 32) | tsl
            lt, tsresol = ifaces.get(iid, (1, 6))
            ts_s = ts_raw / (10 ** tsresol)
            pkt = data[body_off + 20: body_off + 20 + cap_len]
            pkt_no += 1
            yield pkt_no, ts_s, lt, pkt
        elif btype == 3:  # SPB
            cap_len = struct.unpack_from(endian + "I", data, body_off + 12)[0]
            pkt = data[body_off + 16: body_off + 16 + cap_len]
            pkt_no += 1
            yield pkt_no, 0.0, ifaces.get(0, (1, 6))[0], pkt

        off += blen


def _extract_tcp(linktype: int, pkt: bytes) -> dict | None:
    import socket as _sock
    if linktype == 1:
        if len(pkt) < 14 or struct.unpack_from("!H", pkt, 12)[0] != 0x0800:
            return None
        ip_off = 14
    elif len(pkt) >= 20 and (pkt[0] >> 4) == 4:
        ip_off = 0
    else:
        return None

    if len(pkt) < ip_off + 20 or pkt[ip_off + 9] != 6:
        return None

    ihl     = (pkt[ip_off] & 0x0F) * 4
    tot_len = struct.unpack_from("!H", pkt, ip_off + 2)[0]
    src_ip  = _sock.inet_ntoa(pkt[ip_off + 12: ip_off + 16])
    dst_ip  = _sock.inet_ntoa(pkt[ip_off + 16: ip_off + 20])
    tcp_off = ip_off + ihl
    if len(pkt) < tcp_off + 20:
        return None

    sport, dport = struct.unpack_from("!HH", pkt, tcp_off)
    tcp_hlen     = (pkt[tcp_off + 12] >> 4) * 4
    pay_off      = tcp_off + tcp_hlen
    pay_end      = min(len(pkt), ip_off + tot_len)
    payload      = pkt[pay_off:pay_end] if pay_end > pay_off else b""

    return {"src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": sport, "dst_port": dport, "payload": payload}


# ──────────────────────────────────────────────────────────────────────────────
# Cipher helpers
# ──────────────────────────────────────────────────────────────────────────────

def derive_key_from_crib(ciphertext: bytes, body_offset: int, crib: bytes) -> dict[int, int]:
    """
    Given ciphertext body (no length header) and known plaintext 'crib' at body_offset,
    derive as many key byte slots as possible.

    Returns {slot: byte_value} for slots 0..7 that can be derived.
    The ciphertext must already have the 2-byte masked-length header stripped.

    key[body_offset & 7]     = C[body_offset] ^ crib[0]           (first byte: no STATIC_KEY term)
    key[(body_offset+j) & 7] = C[body_offset+j] ^ crib[j]
                               ^ STATIC_KEY[(body_offset+j) & 63]
                               ^ C[body_offset+j-1]                (j > 0)
    """
    slots: dict[int, int] = {}
    n = len(crib)
    body = ciphertext  # already stripped of 2-byte header

    if body_offset + n > len(body):
        return slots

    for j in range(n):
        abs_i = body_offset + j
        if abs_i == 0:
            k = body[0] ^ crib[0]
        else:
            k = (body[abs_i] ^ crib[j]
                 ^ STATIC_KEY[abs_i & 63]
                 ^ body[abs_i - 1]) & 0xFF
        slot = abs_i & 7
        if slot in slots:
            if slots[slot] != k:
                slots[slot] = -1  # conflict
        else:
            slots[slot] = k

    return slots


def key_slots_valid(slots: dict[int, int]) -> tuple[int, int]:
    """Returns (valid_slots, conflict_slots)."""
    valid = sum(1 for v in slots.values() if v >= 0)
    conflict = sum(1 for v in slots.values() if v < 0)
    return valid, conflict


def apply_key_from_slots(body: bytes, slots: dict[int, int]) -> bytes | None:
    """
    Attempt to decode the full body using partially-known key slots.
    Returns None if any needed key slot is missing or conflicted.
    """
    key = [slots.get(i, None) for i in range(8)]
    if any(k is None or k < 0 for k in key):
        return None

    raw = bytearray(body)
    prev = raw[0]
    raw[0] ^= key[0]
    for i in range(1, len(raw)):
        cur    = raw[i]
        raw[i] = (cur ^ STATIC_KEY[i & 63] ^ key[i & 7] ^ prev) & 0xFF
        prev   = cur
    return bytes(raw)


def score_candidate(slots: dict[int, int], crib: bytes, body: bytes,
                    body_offset: int) -> dict:
    """Compute scoring metrics for a crib-drag candidate."""
    valid, conflict = key_slots_valid(slots)
    n_slots_covered = len(slots)

    # Check if all 8 slots are covered (full key recovery possible)
    all_8 = valid == 8 and conflict == 0 and n_slots_covered == 8

    # Verify crib bytes decode correctly (should be tautological, but checks impl)
    crib_verify = True
    for j in range(len(crib)):
        abs_i = body_offset + j
        if abs_i >= len(body):
            crib_verify = False
            break
        slot = abs_i & 7
        k = slots.get(slot, -1)
        if k < 0:
            crib_verify = False
            break
        if abs_i == 0:
            dec = (body[0] ^ k) & 0xFF
        else:
            dec = (body[abs_i] ^ STATIC_KEY[abs_i & 63] ^ k ^ body[abs_i - 1]) & 0xFF
        if dec != crib[j]:
            crib_verify = False
            break

    # Score: weight by valid slots, penalize conflicts
    score = valid * 10 - conflict * 20
    if all_8:
        score += 50
    if crib_verify:
        score += len(crib)

    return {
        "valid_slots":    valid,
        "conflict_slots": conflict,
        "all_8_covered":  all_8,
        "crib_verified":  crib_verify,
        "score":          score,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Crib generation
# ──────────────────────────────────────────────────────────────────────────────

def make_cribs(text: str) -> list[tuple[str, bytes]]:
    """
    Generate all crib variants for a known plaintext ASCII string.
    Returns list of (variant_label, crib_bytes).
    """
    utf16 = text.encode("utf-16-le")
    variants = []

    # Raw UTF-16LE
    if len(utf16) >= MIN_CRIB_LEN:
        variants.append(("utf16le", utf16))

    # UTF-16LE + NUL terminator
    nul = utf16 + b"\x00\x00"
    if len(nul) >= MIN_CRIB_LEN:
        variants.append(("utf16le_nul", nul))

    # 2-byte length (LE) prefix + UTF-16LE (some Aion packet text fields)
    n_chars = len(text)
    for prefix_len in [2, 4]:
        if prefix_len == 2:
            hdr = struct.pack("<H", n_chars)
        else:
            hdr = struct.pack("<I", n_chars)
        v = hdr + utf16
        if len(v) >= MIN_CRIB_LEN:
            variants.append((f"len{prefix_len}+utf16le", v))

    # 2-byte len + UTF-16LE + NUL
    hdr2 = struct.pack("<H", n_chars)
    v2 = hdr2 + utf16 + b"\x00\x00"
    if len(v2) >= MIN_CRIB_LEN:
        variants.append(("len2+utf16le_nul", v2))

    return variants


# ──────────────────────────────────────────────────────────────────────────────
# Main oracle
# ──────────────────────────────────────────────────────────────────────────────

def run_oracle(pcap_path: Path, out_csv: Path) -> list[dict]:
    print(f"[oracle] Parsing {pcap_path.name} ...")

    # Collect all packets with direction info
    all_pkts: list[dict] = []
    for pkt_no, ts, lt, raw in _parse_pcapng(pcap_path):
        p = _extract_tcp(lt, raw)
        if not p or not p["payload"]:
            continue
        # Classify direction
        is_s2c = (p["src_ip"] == SERVER_IP and p["dst_ip"] == CLIENT_IP
                  and p["src_port"] == WORLD_PORT)
        is_c2s = (p["src_ip"] == CLIENT_IP and p["dst_ip"] == SERVER_IP
                  and p["dst_port"] == WORLD_PORT)
        if not (is_s2c or is_c2s):
            continue
        direction = "S2C" if is_s2c else "C2S"
        all_pkts.append({
            "frame":     pkt_no,
            "ts":        ts,
            "direction": direction,
            "payload":   p["payload"],
            "pay_len":   len(p["payload"]),
        })

    s2c_frames = {p["frame"] for p in all_pkts if p["direction"] == "S2C"}
    c2s_frames = {p["frame"] for p in all_pkts if p["direction"] == "C2S"}
    pkt_by_frame = {p["frame"]: p for p in all_pkts}

    print(f"[oracle] Total packets in world flow: {len(all_pkts)}")
    print(f"[oracle] S2C packets: {len(s2c_frames)}, C2S packets: {len(c2s_frames)}")

    candidates: list[dict] = []

    for c2s_frame, label, _spaced in C2S_ORACLE:
        text = LABEL_TO_TEXT[label]
        cribs = make_cribs(text)

        # Find S2C packets in window
        window_s2c = [
            p for p in all_pkts
            if p["direction"] == "S2C"
            and c2s_frame - S2C_WINDOW_BEFORE <= p["frame"] <= c2s_frame + S2C_WINDOW_AFTER
        ]

        print(f"[oracle] {label} (c2s frame {c2s_frame}): "
              f"{len(window_s2c)} S2C in window, {len(cribs)} crib variants")

        for s2c_pkt in window_s2c:
            frame = s2c_pkt["frame"]
            payload = s2c_pkt["payload"]
            pay_len = s2c_pkt["pay_len"]

            # Skip length header (2 bytes)
            if pay_len < 3:
                continue
            body = payload[2:]

            for crib_label, crib in cribs:
                if len(crib) > len(body):
                    continue

                for body_offset in BODY_OFFSETS:
                    if body_offset + len(crib) > len(body):
                        break

                    slots = derive_key_from_crib(body, body_offset, crib)
                    if not slots:
                        continue

                    sc = score_candidate(slots, crib, body, body_offset)
                    if sc["conflict_slots"] > 0:
                        continue  # Skip conflicted candidates
                    if sc["valid_slots"] < 4:
                        continue  # Need at least 4 key slots to be useful

                    candidates.append({
                        "c2s_frame":      c2s_frame,
                        "label":          label,
                        "s2c_frame":      frame,
                        "frame_delta":    frame - c2s_frame,
                        "s2c_pay_len":    pay_len,
                        "body_len":       len(body),
                        "crib_variant":   crib_label,
                        "crib_len":       len(crib),
                        "body_offset":    body_offset,
                        "valid_slots":    sc["valid_slots"],
                        "conflict_slots": sc["conflict_slots"],
                        "all_8_covered":  sc["all_8_covered"],
                        "crib_verified":  sc["crib_verified"],
                        "score":          sc["score"],
                    })

    # Sort by score descending
    candidates.sort(key=lambda x: -x["score"])

    # Write candidates CSV (no raw bytes)
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        if candidates:
            writer = csv.DictWriter(f, fieldnames=list(candidates[0].keys()))
            writer.writeheader()
            writer.writerows(candidates)
        else:
            f.write("c2s_frame,label,s2c_frame,frame_delta,s2c_pay_len,body_len,"
                    "crib_variant,crib_len,body_offset,valid_slots,conflict_slots,"
                    "all_8_covered,crib_verified,score\n")

    print(f"[oracle] Total candidates: {len(candidates)}")
    print(f"[oracle] Written to {out_csv}")
    return candidates


if __name__ == "__main__":
    pcap = Path(sys.argv[1]) if len(sys.argv) > 1 else \
           Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\startup_world_open_kxseq.pcapng")
    out  = Path(sys.argv[2]) if len(sys.argv) > 2 else \
           Path(r"artifacts\pass636_antigravity_s2c_crib_candidates.csv")
    run_oracle(pcap, out)
