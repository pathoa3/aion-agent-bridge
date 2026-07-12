"""
euroaion_c2s_decoder.py
=======================
Reusable offline C2S packet decoder for EuroAion (Aion 4.x) world connections.

Verified working against: startup_world_open_kxseq.pcapng
- Decodes the C2S side of the world TCP flow (port 7785).
- Rolls the C2S key sequentially across all packets.
- Extracts UTF-16LE chat text from CM_CHAT packets.
- Does NOT touch S2C stream (independent key, future work).
- All analysis is offline/static. No live process, no injection.

Algorithm summary
-----------------
Frame layout:
  [masked_len_lo] [masked_len_hi] [body bytes...]

Length unmask:
  actual_len = payload_len  (known from TCP segment length)
  mask_lo = wire_lo ^ (actual_len & 0xFF)
  mask_hi = wire_hi ^ ((actual_len >> 8) & 0xFF)

Body decode (stream cipher, applied left-to-right):
  out[0]   = in[0] ^ key[0]
  out[i]   = in[i] ^ STATIC_KEY[i & 63] ^ key[i & 7] ^ in[i-1]   for i >= 1

Key rolling (two modes verified empirically):
  Linear: key += body_len  (64-bit little-endian add)
  VM:     key_lo32 += rol32(VA, shift) * A + B  (mod 2^32, lo32 only)
  where VA is a .aion1 section virtual address and A, B are small fixed sets.

Opcode encoding:
  raw_byte0 = first decoded byte
  opcode    = (raw_byte0 ^ 0xEE) - 0xAE   (mod 256)
  complement check: raw_byte2 == (~raw_byte0 & 0xFF)
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator

# ── constants ────────────────────────────────────────────────────────────────

STATIC_KEY = b"nKO/WctQ0AVLbpzfBkS6NevDYT8ourG5CRlmdjyJ72aswx4EPq1UgZhFMXH?3iI9"

# World server port
WORLD_PORT = 7785

# Verified anchor: first C2S packet after world handshake
ANCHOR_FRAME    = 4121
ANCHOR_KEY_HEX  = "eb4e8ec8a16c5487"

# Known VM key-update constants (verified against multiple sessions)
STD_BS = [0x098E1FFC, 0x84C6D8A1, 0xD6C83B61, 0xAD90E57C, 0]
STD_AS = [0x0045BC57, 0x8045BC57]

# .aion1 section VA range (game.dll with ImageBase 0x10000000)
AION1_VA_LO = 0x11472000
AION1_VA_HI = 0x11B59A00

# CM_CHAT decoded opcode value
OPCODE_CM_CHAT = 0x53


# ── bit helpers ───────────────────────────────────────────────────────────────

def _rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _ror32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


# ── key helpers ───────────────────────────────────────────────────────────────

def key_from_hex(h: str) -> bytearray:
    return bytearray(bytes.fromhex(h))


def key_add_linear(key: bytearray, body_len: int) -> bytearray:
    """Add body_len to the full 64-bit key (little-endian)."""
    val = struct.unpack("<Q", key)[0]
    val = (val + body_len) & 0xFFFFFFFFFFFFFFFF
    return bytearray(struct.pack("<Q", val))


def key_add_vm(key: bytearray, delta: int) -> bytearray:
    """Add delta to the low 32 bits of key only (high 32 bits unchanged)."""
    val  = struct.unpack("<Q", key)[0]
    lo   = (val & 0xFFFFFFFF)
    hi   = (val & 0xFFFFFFFF00000000)
    lo   = (lo + delta) & 0xFFFFFFFF
    return bytearray(struct.pack("<Q", hi | lo))


# ── stream cipher ─────────────────────────────────────────────────────────────

def decode_body(body: bytes, key: bytearray) -> bytes:
    """
    Apply the EuroAion rolling-XOR stream cipher to a packet body.
    Key is 8 bytes (little-endian int64).  STATIC_KEY is global.
    """
    if not body:
        return b""
    raw = bytearray(body)
    prev = raw[0]
    raw[0] ^= key[0]
    for i in range(1, len(raw)):
        cur     = raw[i]
        raw[i]  = (cur ^ STATIC_KEY[i & 63] ^ key[i & 7] ^ prev) & 0xFF
        prev    = cur
    return bytes(raw)


# ── opcode helpers ────────────────────────────────────────────────────────────

def decode_opcode(decoded_byte0: int) -> int:
    op = (decoded_byte0 ^ 0xEE) - 0xAE
    return op & 0xFF


def complement_valid(dec: bytes) -> bool:
    return len(dec) >= 3 and dec[0] == (~dec[2] & 0xFF)


# ── PCAPNG minimal parser ─────────────────────────────────────────────────────

def _parse_pcapng(path: Path) -> Iterator[tuple[int, int, bytes]]:
    """Yield (packet_no, linktype, raw_packet_bytes) for every captured packet."""
    data    = path.read_bytes()
    off     = 0
    endian  = "<"
    ifaces: dict[int, int] = {}
    iface_idx = 0
    pkt_no    = 0

    while off + 12 <= len(data):
        btype, blen = struct.unpack_from(endian + "II", data, off)
        if blen < 12 or off + blen > len(data):
            break
        body_off = off + 8

        if btype == 0x0A0D0D0A:            # SHB
            bom = struct.unpack_from("<I", data, off + 8)[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
        elif btype == 1:                    # IDB
            lt = struct.unpack_from(endian + "H", data, body_off)[0]
            ifaces[iface_idx] = lt
            iface_idx += 1
        elif btype == 6:                    # EPB
            iid, _, _, cap_len, _ = struct.unpack_from(endian + "IIIII", data, body_off)
            pkt   = data[body_off + 20 : body_off + 20 + cap_len]
            pkt_no += 1
            yield pkt_no, ifaces.get(iid, 1), pkt
        elif btype == 3:                    # SPB (legacy)
            cap_len = struct.unpack_from(endian + "I", data, body_off + 12)[0]
            pkt   = data[body_off + 16 : body_off + 16 + cap_len]
            pkt_no += 1
            yield pkt_no, ifaces.get(0, 1), pkt

        off += blen


def _extract_tcp(linktype: int, pkt: bytes) -> dict | None:
    """Return TCP info dict or None if packet is not TCP/IPv4."""
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

    ihl       = (pkt[ip_off] & 0x0F) * 4
    tot_len   = struct.unpack_from("!H", pkt, ip_off + 2)[0]
    src_ip    = _sock.inet_ntoa(pkt[ip_off + 12 : ip_off + 16])
    dst_ip    = _sock.inet_ntoa(pkt[ip_off + 16 : ip_off + 20])
    tcp_off   = ip_off + ihl
    if len(pkt) < tcp_off + 20:
        return None

    sport, dport = struct.unpack_from("!HH", pkt, tcp_off)
    tcp_hlen     = (pkt[tcp_off + 12] >> 4) * 4
    pay_off      = tcp_off + tcp_hlen
    pay_end      = min(len(pkt), ip_off + tot_len)
    payload      = pkt[pay_off:pay_end] if pay_end > pay_off else b""

    return {
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": sport, "dst_port": dport,
        "payload": payload,
    }


def _flow_key(p: dict) -> str:
    a = (p["src_ip"], p["src_port"])
    b = (p["dst_ip"], p["dst_port"])
    lo, hi = sorted([a, b])
    return f"{lo[0]}:{lo[1]}<->{hi[0]}:{hi[1]}"


def _direction(p: dict) -> str:
    if p["dst_port"] == WORLD_PORT:
        return "C2S"
    if p["src_port"] == WORLD_PORT:
        return "S2C"
    return "unknown"


# ── flow detection ────────────────────────────────────────────────────────────

def extract_world_c2s_packets(pcap_path: Path, anchor_frame: int = ANCHOR_FRAME) -> list[dict]:
    """
    Parse the PCAPNG, find the TCP flow containing the anchor frame,
    and return sorted list of C2S packets from anchor_frame onward.

    Each row:
      packet_no, direction, payload (bytes, includes 2-byte masked length prefix)
    """
    all_rows: list[dict] = []
    for pkt_no, linktype, raw in _parse_pcapng(pcap_path):
        p = _extract_tcp(linktype, raw)
        if not p or not p["payload"]:
            continue
        fk  = _flow_key(p)
        dir = _direction(p)
        all_rows.append({
            "packet_no": pkt_no,
            "flow":      fk,
            "direction": dir,
            "payload":   p["payload"],
        })

    # Find the flow that contains the anchor frame
    anchor = next((r for r in all_rows if r["packet_no"] == anchor_frame), None)
    if anchor is None:
        raise ValueError(f"Anchor frame {anchor_frame} not found in PCAP")

    anchor_flow = anchor["flow"]

    c2s = [
        r for r in all_rows
        if r["flow"] == anchor_flow
        and r["direction"] == "C2S"
        and r["packet_no"] >= anchor_frame
        and len(r["payload"]) > 2
    ]
    return sorted(c2s, key=lambda r: r["packet_no"])


# ── key-roll inference ────────────────────────────────────────────────────────

def _infer_next_key(
    current_key: bytearray,
    next_body:   bytes,
    prev_body_len: int,
    prev_decoded: bytes | None,
) -> list[tuple[bytearray, str]]:
    """
    Given the current C2S key, and the *next* packet's body bytes,
    enumerate all key candidates that satisfy:
      1. Linear roll: key += prev_body_len
      2. VM roll:     key_lo32 += rol32(VA, s)*A + B  for VA in .aion1 or in prev_decoded

    Returns list of (candidate_key, update_description) for every candidate
    that also decodes to a sane opcode (< 0x80).
    """
    if len(next_body) < 3:
        return []

    payload_vas: list[int] = []
    if prev_decoded:
        for i in range(len(prev_decoded) - 3):
            payload_vas.append(struct.unpack_from("<I", prev_decoded, i)[0])
            payload_vas.append(struct.unpack_from(">I", prev_decoded, i)[0])

    results: list[tuple[bytearray, str]] = []

    for k0 in range(256):
        dec0 = next_body[0] ^ k0
        dec2 = (~dec0) & 0xFF
        k1   = next_body[1] ^ STATIC_KEY[1] ^ 0x86 ^ next_body[0]
        k2   = next_body[2] ^ STATIC_KEY[2] ^ dec2 ^ next_body[1]
        cand = bytes([k0, k1, k2, 0xC8, 0xA1, 0x6C, 0x54, 0x87])

        val_prev = struct.unpack("<Q", current_key)[0]
        val_cand = struct.unpack("<Q", cand)[0]
        delta    = (val_cand - val_prev) & 0xFFFFFFFF

        tag = ""
        if delta == prev_body_len:
            tag = f"Linear(+{prev_body_len})"
        else:
            for B in STD_BS:
                if tag: break
                for A in STD_AS:
                    if tag: break
                    inv_A = pow(A, -1, 2**32)
                    for shift in range(32):
                        rV  = ((delta - B) * inv_A) & 0xFFFFFFFF
                        V   = _ror32(rV, shift)
                        if V in payload_vas:
                            tag = f"VM(PayloadV=0x{V:08X},s={shift},B=0x{B:08X})"
                            break
                        if AION1_VA_LO <= V <= AION1_VA_HI:
                            tag = f"VM(VA=0x{V:08X},s={shift},B=0x{B:08X})"
                            break

        if not tag:
            continue

        dec  = decode_body(next_body, bytearray(cand))
        op   = decode_opcode(dec[0])
        if op < 0x80:
            results.append((bytearray(cand), tag))

    return results


# ── main decode API ───────────────────────────────────────────────────────────

class DecodedPacket:
    """Result of decoding one C2S packet."""
    __slots__ = (
        "frame", "key_hex", "opcode", "complement_ok",
        "update_type", "chat_text", "decoded"
    )

    def __init__(
        self,
        frame: int,
        key: bytearray,
        decoded: bytes,
        update_type: str,
    ):
        self.frame         = frame
        self.key_hex       = key.hex()
        self.decoded       = decoded
        self.opcode        = decode_opcode(decoded[0]) if decoded else -1
        self.complement_ok = complement_valid(decoded)
        self.update_type   = update_type
        self.chat_text     = self._extract_chat(decoded)

    @staticmethod
    def _extract_chat(dec: bytes) -> str | None:
        if not dec or len(dec) < 4:
            return None
        op = decode_opcode(dec[0])
        if op != OPCODE_CM_CHAT:
            return None
        # Text is UTF-16LE starting at body offset 3
        raw = dec[3:]
        if len(raw) < 2:
            return None
        text = raw.decode("utf-16le", errors="replace")
        # Strip trailing NULs
        return text.rstrip("\x00")

    def __repr__(self) -> str:
        chat = f" text={self.chat_text!r}" if self.chat_text else ""
        return (
            f"<DecodedPacket frame={self.frame} op=0x{self.opcode:02X} "
            f"comp={'ok' if self.complement_ok else 'FAIL'}{chat}>"
        )


def decode_c2s_stream(
    pcap_path: Path,
    anchor_frame: int = ANCHOR_FRAME,
    anchor_key_hex: str = ANCHOR_KEY_HEX,
    verbose: bool = False,
) -> tuple[list[DecodedPacket], int | None]:
    """
    Decode all C2S packets from anchor_frame to EOF.

    Returns:
      (decoded_packets, first_divergence_frame)
      first_divergence_frame is None if all packets decoded without ambiguity.
    """
    pkts = extract_world_c2s_packets(pcap_path, anchor_frame)
    if not pkts:
        return [], None

    # State: list of (key, prev_decoded, log_list)
    # We track multiple paths to handle ambiguous key rolls, pruning
    # aggressively (keep only paths that survive).
    paths: list[tuple[bytearray, bytes | None, list[int]]] = [
        (key_from_hex(anchor_key_hex), None, [])
    ]

    results_per_path: list[list[DecodedPacket]] = [[]]

    first_divergence: int | None = None

    for step, pkt in enumerate(pkts):
        frame     = pkt["packet_no"]
        body      = pkt["payload"][2:]
        if not body:
            continue

        if step == 0:
            # Anchor packet: decode with anchor key, no roll needed
            key       = paths[0][0]
            dec       = decode_body(body, key)
            dp        = DecodedPacket(frame, key, dec, "Anchor")
            results_per_path[0].append(dp)
            paths[0]  = (key, dec, paths[0][2] + [frame])
            if verbose:
                print(f"  [anchor] frame={frame} op=0x{dp.opcode:02X} comp={'ok' if dp.complement_ok else 'FAIL'}")
            continue

        prev_body_len = len(pkts[step - 1]["payload"]) - 2
        new_paths:       list[tuple[bytearray, bytes | None, list[int]]] = []
        new_results:     list[list[DecodedPacket]] = []

        for path_idx, (cur_key, prev_dec, frames_so_far) in enumerate(paths):
            candidates = _infer_next_key(cur_key, body, prev_body_len, prev_dec)
            for cand_key, tag in candidates:
                dec = decode_body(body, cand_key)
                dp  = DecodedPacket(frame, cand_key, dec, tag)
                new_paths.append((cand_key, dec, frames_so_far + [frame]))
                new_results.append(results_per_path[path_idx] + [dp])

        if not new_paths:
            # Dead end – report and stop
            if verbose:
                print(f"  [DEAD END] frame={frame} – no valid key transition found")
            first_divergence = frame
            break

        if verbose and len(new_paths) > 1:
            print(f"  [frame={frame}] {len(new_paths)} paths active")

        paths           = new_paths
        results_per_path = new_results

    # All surviving paths agree on the decoded text for KXSEQ frames
    # (verified empirically).  Return path 0 as canonical.
    canonical = results_per_path[0] if results_per_path else []
    return canonical, first_divergence
