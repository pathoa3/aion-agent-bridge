#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
ART = REPO / "artifacts"
sys.path.insert(0, str(REPO / "tools" / "pass647_dynamic_world_port"))
from pcap_dynamic import parse_pcapng, write_csv  # type: ignore

STATIC_KEY = b"nKO/WctQ0AVLbpzfBkS6NevDYT8ourG5CRlmdjyJ72aswx4EPq1UgZhFMXH?3iI9"


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def load_world_port() -> int | None:
    dec = ART / "pass647_dynamic_world_port_decision.json"
    if dec.exists():
        data = json.loads(dec.read_text(encoding="utf-8"))
        port = data.get("actual_world_port_detected")
        return int(port) if port else None
    return None


def crib_variants(text: str, channel: str):
    marker_utf16 = text.encode("utf-16le")
    yield "utf16le_marker", marker_utf16
    yield "utf16le_marker_nul", marker_utf16 + b"\x00\x00"
    if channel == "whisper":
        visible = "::Spirips Whispers: " + text
        yield "visible_whisper_utf16le", visible.encode("utf-16le")
        yield "visible_whisper_utf16le_nul", visible.encode("utf-16le") + b"\x00\x00"
    if channel == "group":
        visible = "Spirips: " + text
        yield "visible_group_utf16le", visible.encode("utf-16le")
        yield "visible_group_utf16le_nul", visible.encode("utf-16le") + b"\x00\x00"
    yield "unknown_prefix_window_utf16le", marker_utf16


def derive_slots(body: bytes, body_offset: int, crib: bytes):
    slots: dict[int, int] = {}
    conflicts = 0
    if body_offset < 0 or body_offset + len(crib) > len(body):
        return 0, 8, "none"
    for j, plain in enumerate(crib):
        abs_i = body_offset + j
        if abs_i == 0:
            val = body[0] ^ plain
        else:
            val = body[abs_i] ^ plain ^ STATIC_KEY[abs_i & 63] ^ body[abs_i - 1]
        slot = abs_i & 7
        if slot in slots and slots[slot] != val:
            conflicts += 1
        else:
            slots[slot] = val
    good = len(slots)
    # Internal-only anonymized signature for repeat comparison, never written.
    sig = ";".join(f"{k}:{v}" for k, v in sorted(slots.items()))
    return good, conflicts, sig


def window_strategy(delta_ms: int | None) -> str:
    if delta_ms is None:
        return "whole_flow_fallback"
    ad = abs(delta_ms)
    if ad <= 3000:
        return "exact_3s"
    if ad <= 10000:
        return "window_10s"
    if ad <= 30000:
        return "window_30s"
    return "whole_flow_fallback"


def load_marker_rows() -> list[dict[str, str]]:
    rows = [r for r in read_csv(ART / "pass647_marker_correlation_7780_10242.csv") if r.get("server_port") == "7780"]
    return rows


def candidate_packets_for_marker(marker: dict[str, str], packets_by_frame, packets, port: int):
    frames = set()
    if marker.get("nearest_s2c_frame"):
        frames.add(int(marker["nearest_s2c_frame"]))
    # Add packets in time windows for this marker by using the nearest packet timestamp as anchor.
    anchor = packets_by_frame.get(int(marker["nearest_s2c_frame"])) if marker.get("nearest_s2c_frame") else None
    if anchor and anchor.ts is not None:
        for p in packets:
            if p.server_port_guess == port and p.direction_guess == "S2C" and p.payload_len > 0 and p.ts is not None:
                if abs(p.ts - anchor.ts) <= 30:
                    frames.add(p.frame)
    return [packets_by_frame[f] for f in sorted(frames) if f in packets_by_frame]


def scan_candidates(limit_per_marker: int = 40) -> tuple[list[dict[str, object]], dict[str, set[str]]]:
    port = load_world_port()
    if port is None:
        return [], {}
    packets = parse_pcapng(PCAP)
    world_packets = [p for p in packets if p.server_port_guess == port and p.direction_guess == "S2C" and p.payload_len > 0]
    packets_by_frame = {p.frame: p for p in world_packets}
    markers = load_marker_rows()
    repeat_sigs: dict[str, set[str]] = defaultdict(set)
    raw_rows = []
    seq = 0
    for m in markers:
        text = m.get("marker_text", "")
        channel = m.get("channel_guess", "unknown")
        delta = int(m["delta_ms"]) if m.get("delta_ms") not in (None, "") else None
        strategy = window_strategy(delta)
        packets_to_scan = candidate_packets_for_marker(m, packets_by_frame, world_packets, port)
        marker_hits = []
        for pkt in packets_to_scan:
            body = pkt.payload[2:] if len(pkt.payload) > 2 else pkt.payload
            if len(body) < 8:
                continue
            for variant, crib in crib_variants(text, channel):
                if len(crib) < 8 or len(crib) > len(body):
                    continue
                # Step by 2 for UTF-16 aligned hypotheses, plus offset 0/1 coverage through start parity.
                for off in range(0, max(0, len(body) - len(crib) + 1), 2):
                    slots, conflicts, sig = derive_slots(body, off, crib)
                    if slots >= 8 and conflicts == 0:
                        structural = min(100, 40 + len(crib) // 2 + (20 if slots == 8 else 0))
                        marker_hits.append((structural, pkt, variant, off, slots, conflicts, sig))
        marker_hits.sort(key=lambda x: (x[0], x[4], -x[5]), reverse=True)
        for structural, pkt, variant, off, slots, conflicts, sig in marker_hits[:limit_per_marker]:
            seq += 1
            cid = f"pass648_{seq:05d}"
            repeat_sigs[text].add(f"{variant}|{off}|{sig}")
            raw_rows.append({
                "candidate_id": cid,
                "marker_text": text,
                "channel_guess": channel,
                "frame": pkt.frame,
                "window_strategy": strategy,
                "crib_variant": variant,
                "payload_len": pkt.payload_len,
                "body_offset": off,
                "slots_recovered": slots,
                "conflict_slots": conflicts,
                "all_8_covered": str(slots == 8).lower(),
                "repeat_consistency": "pending",
                "structural_score": structural,
                "confidence": "medium_candidate" if structural >= 60 else "low_candidate",
                "reason": "bounded crib-derived slot consistency only; derived key bytes not written",
                "_sig": sig,
            })
    # Fill repeat consistency without writing signatures.
    counts = Counter(r["marker_text"] for r in markers)
    for r in raw_rows:
        text = str(r["marker_text"])
        if counts[text] < 2:
            r["repeat_consistency"] = "not_repeated_marker"
        else:
            r["repeat_consistency"] = "consistent" if len(repeat_sigs[text]) == 1 else "not_consistent"
    for r in raw_rows:
        r.pop("_sig", None)
    return raw_rows, repeat_sigs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ART / "pass648_s2c_oracle_candidates.csv")
    ns = ap.parse_args()
    rows, _ = scan_candidates()
    fields = ["candidate_id","marker_text","channel_guess","frame","window_strategy","crib_variant","payload_len","body_offset","slots_recovered","conflict_slots","all_8_covered","repeat_consistency","structural_score","confidence","reason"]
    write_csv(ns.out, rows, fields)
    print(json.dumps({"candidate_count": len(rows), "out": str(ns.out)}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
