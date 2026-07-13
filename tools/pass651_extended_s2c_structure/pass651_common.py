#!/usr/bin/env python3
from __future__ import annotations

import csv
import datetime as dt
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

REPO = Path(__file__).resolve().parents[2]
ART = REPO / "artifacts"
PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
LOG = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt")
LOCAL_OUT = Path(r"C:\AionTools\aion_decoder_agent\outbox\pass651_local_payload_triage")
sys.path.insert(0, str(REPO / "tools" / "pass647_dynamic_world_port"))
from pcap_dynamic import parse_pcapng, iso_time, write_csv  # type: ignore

STATIC_KEY = b"nKO/WctQ0AVLbpzfBkS6NevDYT8ourG5CRlmdjyJ72aswx4EPq1UgZhFMXH?3iI9"


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def parse_ts(s: str):
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return dt.datetime.strptime(s.strip(), fmt).timestamp()
        except Exception:
            pass
    return None


def load_log_rows() -> list[dict[str, str]]:
    with LOG.open("r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def load_current_markers() -> tuple[list[dict], int, int]:
    rows = load_log_rows()
    old = sum(1 for r in rows if (r.get("visible_text") or "").strip().startswith("S2C_ORACLE_"))
    markers = []
    for r in rows:
        text = (r.get("visible_text") or "").strip()
        notes = (r.get("notes") or "").lower()
        direction = (r.get("direction") or "").upper()
        if direction == "S2C" and text.startswith("S2C_A_") and "whisper" in notes and not text.endswith("G"):
            markers.append({
                "marker_index": len(markers) + 1,
                "marker_text": text,
                "marker_len_ascii": len(text.encode("ascii", errors="ignore")),
                "marker_len_utf16le": len(text.encode("utf-16le", errors="ignore")),
                "logged_time": r.get("timestamp_local", ""),
                "ts": parse_ts(r.get("timestamp_local", "")),
                "channel_guess": "whisper",
                "repeat_id": text,
            })
    return markers, old, len(rows)


def flow_role(port: int) -> str:
    return "world_game_candidate" if port == 7780 else "chat_sidechannel_candidate" if port == 10242 else "other"


def packets_for(packets, port: int, direction: str | None = None):
    out = [p for p in packets if p.server_port_guess == port and p.payload_len > 0]
    if direction:
        out = [p for p in out if p.direction_guess == direction]
    return out


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def byte_stats(data: bytes) -> dict[str, float]:
    if not data:
        return {"entropy": 0.0, "zero_ratio": 0.0, "printable_ratio": 0.0, "utf16_likeness": 0.0}
    zeros = data.count(0) / len(data)
    printable = sum(1 for b in data if 32 <= b <= 126) / len(data)
    odd_zeros = sum(1 for i in range(1, len(data), 2) if data[i] == 0)
    odd_count = max(1, len(range(1, len(data), 2)))
    return {"entropy": entropy(data), "zero_ratio": zeros, "printable_ratio": printable, "utf16_likeness": odd_zeros / odd_count}


def crib_variants(text: str):
    utf16 = text.encode("utf-16le")
    yield "ascii_marker", text.encode("ascii", errors="ignore")
    yield "utf16le_marker", utf16
    yield "utf16le_marker_nul", utf16 + b"\x00\x00"
    visible = "::Spirips Whispers: " + text
    yield "visible_whisper_utf16le", visible.encode("utf-16le")
    yield "unknown_prefix_window_utf16le", utf16


def derive_slots(stream: bytes, offset: int, crib: bytes):
    slots: dict[int, int] = {}
    conflicts = 0
    if offset < 1 or offset + len(crib) > len(stream):
        return 0, 8, ""
    for j, plain in enumerate(crib):
        pos = offset + j
        phase = pos & 63
        slot = pos & 7
        if phase == 0:
            val = stream[pos] ^ plain
        else:
            val = stream[pos] ^ plain ^ STATIC_KEY[phase] ^ stream[pos - 1]
        if slot in slots and slots[slot] != val:
            conflicts += 1
        else:
            slots[slot] = val
    sig = ";".join(f"{k}:{v}" for k, v in sorted(slots.items()))
    return len(slots), conflicts, sig


def build_stream_ranges(packets, port: int, direction: str):
    selected = packets_for(packets, port, direction)
    selected.sort(key=lambda p: (p.ts or 0, p.frame))
    offset = 0
    ranges = []
    chunks = []
    for p in selected:
        start = offset
        chunks.append(p.payload)
        offset += p.payload_len
        ranges.append({"frame": p.frame, "ts": p.ts, "start": start, "end": offset, "len": p.payload_len})
    return b"".join(chunks), ranges


def local_window_packets(packets, marker: dict, port: int, direction: str | None, window: float):
    ts = marker["ts"]
    if ts is None:
        return []
    rows = packets_for(packets, port, direction)
    return [p for p in rows if p.ts is not None and abs(p.ts - ts) <= window]
