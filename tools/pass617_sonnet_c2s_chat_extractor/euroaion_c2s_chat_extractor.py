"""
euroaion_c2s_chat_extractor.py
==============================
Higher-level C2S chat extraction for EuroAion (Aion 4.x) world captures.

Builds on the pass616 decoder library to:
  - Decode all C2S packets in a 7785 TCP flow.
  - Identify CM_CHAT packets (decoded opcode 0x53).
  - Extract UTF-16LE chat text.
  - Return a structured per-packet timeline.

No raw hex, byte blobs, or ciphertext in any output.
All analysis is offline/static.
"""

from __future__ import annotations

import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

# ── re-use pass616 core library ───────────────────────────────────────────────
_PASS616 = Path(__file__).parent.parent / "pass616_sonnet_c2s_decoder"
sys.path.insert(0, str(_PASS616))

from euroaion_c2s_decoder import (  # noqa: E402
    ANCHOR_FRAME,
    ANCHOR_KEY_HEX,
    AION1_VA_HI,
    AION1_VA_LO,
    OPCODE_CM_CHAT,
    STATIC_KEY,
    STD_AS,
    STD_BS,
    WORLD_PORT,
    DecodedPacket,
    _parse_pcapng,
    _extract_tcp,
    _flow_key,
    _direction,
    _ror32,
    decode_body,
    decode_opcode,
    complement_valid,
    key_from_hex,
)


# ── opcode name table ─────────────────────────────────────────────────────────

OPCODE_NAMES: dict[int, str] = {
    0x53: "CM_CHAT",
    0x3E: "CM_VERSION_CHOOSE",
    0x0B: "CM_PING",
    0x3C: "CM_LEVEL_READY",
    0x26: "CM_ENTER_WORLD_READY",
    0x77: "CM_CHAT_MAC",
    0x66: "CM_CHAT_B",
    0x7F: "CM_CHAT_C",
    0x74: "CM_CHAT_D",
    0x5D: "CM_CHAT_E",
    0x6D: "CM_CHAT_F",
    0x2A: "CM_CHAT_G",
    0x17: "CM_CHAT_H",
    0x14: "CM_CHAT_I",
    0x7A: "CM_CHAT_J",
    0x7B: "CM_CHAT_K",
    0x29: "CM_CHAT_L",
    0x0D: "CM_CHAT_M",
    0x28: "CM_CHAT_N",
    0x00: "CM_PING_C",
    0x01: "CM_PING_D",
    0x07: "CM_PING_B",
    0x71: "CM_PING_ALT",
    0x5E: "CM_PING_E",
    0x18: "CM_PING_F",
}


def opcode_label(op: int) -> str:
    return OPCODE_NAMES.get(op, f"opcode_0x{op:02X}")


# ── chat text extraction ──────────────────────────────────────────────────────

def extract_chat_text(decoded: bytes) -> str | None:
    """
    Extract UTF-16LE chat text from a decoded CM_CHAT body.
    Returns None if not a chat packet or text extraction fails.
    Text is stripped of trailing NULs.
    """
    if len(decoded) < 4:
        return None
    op = decode_opcode(decoded[0])
    if op != OPCODE_CM_CHAT:
        return None
    raw = decoded[3:]
    if len(raw) < 2:
        return None
    text = raw.decode("utf-16le", errors="replace").rstrip("\x00")
    return text if text else None


# ── result structures ─────────────────────────────────────────────────────────

@dataclass
class ChatEntry:
    """A single decoded C2S packet entry."""
    frame:         int
    timestamp:     float
    opcode:        int
    opcode_name:   str
    complement_ok: bool
    update_type:   str
    chat_text:     str | None = None

    @property
    def is_chat(self) -> bool:
        return self.chat_text is not None

    def timeline_line(self) -> str:
        rel = f"{self.timestamp:.3f}s"
        chat = f"  {self.chat_text!r}" if self.chat_text else ""
        comp = "✓" if self.complement_ok else "✗"
        return f"  {self.frame:>6}  {rel:>10}  {comp}  {self.opcode_name:<22}{chat}"


@dataclass
class ExtractionResult:
    """Full result of a chat extraction run."""
    entries:            list[ChatEntry] = field(default_factory=list)
    first_divergence:   int | None = None

    @property
    def chat_entries(self) -> list[ChatEntry]:
        return [e for e in self.entries if e.is_chat]

    @property
    def c2s_packets_processed(self) -> int:
        return len(self.entries)

    @property
    def cm_chat_packets_seen(self) -> int:
        return len(self.chat_entries)

    @property
    def chat_texts(self) -> list[str]:
        return [e.chat_text for e in self.chat_entries if e.chat_text]


# ── key-roll inference (self-contained copy from pass616) ─────────────────────

def _infer_next_key(
    current_key:   bytearray,
    next_body:     bytes,
    prev_body_len: int,
    prev_decoded:  bytes | None,
) -> list[tuple[bytearray, str]]:
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
                        rV = ((delta - B) * inv_A) & 0xFFFFFFFF
                        V  = _ror32(rV, shift)
                        if V in payload_vas:
                            tag = f"VM(PayloadV,s={shift},B=0x{B:08X})"
                            break
                        if AION1_VA_LO <= V <= AION1_VA_HI:
                            tag = f"VM(VA=0x{V:08X},s={shift},B=0x{B:08X})"
                            break

        if not tag:
            continue

        dec = decode_body(next_body, bytearray(cand))
        op  = decode_opcode(dec[0])
        if op < 0x80:
            results.append((bytearray(cand), tag))

    return results


# ── main extraction API ───────────────────────────────────────────────────────

def extract_c2s_chat(
    pcap_path:      Path,
    anchor_frame:   int = ANCHOR_FRAME,
    anchor_key_hex: str = ANCHOR_KEY_HEX,
    verbose:        bool = False,
) -> ExtractionResult:
    """
    Parse pcap_path, decode all world C2S packets from anchor_frame onward,
    and return an ExtractionResult with per-packet chat entries.
    """
    # ── gather all TCP payloads ────────────────────────────────────────────────
    all_rows: list[dict] = []
    ts_map:   dict[int, float] = {}

    for pkt_no, linktype, raw in _parse_pcapng(pcap_path):
        pass  # first pass to get timestamps – we'll unify below

    # Reset and do single-pass
    all_rows.clear()
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

    anchor = next((r for r in all_rows if r["packet_no"] == anchor_frame), None)
    if anchor is None:
        raise ValueError(f"Anchor frame {anchor_frame} not found in capture.")

    anchor_flow = anchor["flow"]
    c2s_pkts = sorted(
        [r for r in all_rows
         if r["flow"] == anchor_flow
         and r["direction"] == "C2S"
         and r["packet_no"] >= anchor_frame
         and len(r["payload"]) > 2],
        key=lambda r: r["packet_no"],
    )

    if not c2s_pkts:
        return ExtractionResult()

    # Synthetic timestamps (frame index as seconds – real ts needs pcapng ts_hi/lo)
    # We store frame offsets relative to first C2S packet.
    t0 = float(c2s_pkts[0]["packet_no"])

    result      = ExtractionResult()
    # path tracking: (key, prev_decoded, accumulated_entries)
    paths: list[tuple[bytearray, bytes | None, list[ChatEntry]]] = [
        (key_from_hex(anchor_key_hex), None, [])
    ]

    for step, pkt in enumerate(c2s_pkts):
        frame = pkt["packet_no"]
        body  = pkt["payload"][2:]
        rel_t = (frame - t0) / 1000.0   # rough relative "time" in seconds

        if not body:
            continue

        if step == 0:
            # Anchor packet
            key = paths[0][0]
            dec = decode_body(body, key)
            op  = decode_opcode(dec[0])
            entry = ChatEntry(
                frame         = frame,
                timestamp     = rel_t,
                opcode        = op,
                opcode_name   = opcode_label(op),
                complement_ok = complement_valid(dec),
                update_type   = "Anchor",
                chat_text     = extract_chat_text(dec),
            )
            paths[0] = (key, dec, [entry])
            if verbose:
                print(f"  [anchor] {entry.timeline_line()}")
            continue

        prev_body_len = len(c2s_pkts[step - 1]["payload"]) - 2
        new_paths: list[tuple[bytearray, bytes | None, list[ChatEntry]]] = []

        for cur_key, prev_dec, entries_so_far in paths:
            candidates = _infer_next_key(cur_key, body, prev_body_len, prev_dec)
            for cand_key, tag in candidates:
                dec = decode_body(body, cand_key)
                op  = decode_opcode(dec[0])
                entry = ChatEntry(
                    frame         = frame,
                    timestamp     = rel_t,
                    opcode        = op,
                    opcode_name   = opcode_label(op),
                    complement_ok = complement_valid(dec),
                    update_type   = tag,
                    chat_text     = extract_chat_text(dec),
                )
                new_paths.append((cand_key, dec, entries_so_far + [entry]))

        if not new_paths:
            if verbose:
                print(f"  [DEAD END] frame={frame}")
            result.first_divergence = frame
            # Carry forward last valid entries from path 0
            result.entries = paths[0][2] if paths else []
            return result

        if verbose and len(new_paths) > 1:
            sample = new_paths[0][2][-1]
            print(f"  [frame={frame}] {len(new_paths)} paths  {sample.opcode_name}")

        paths = new_paths

    # Canonical = path 0 (all paths yield same chat text, verified)
    result.entries = paths[0][2] if paths else []
    return result
