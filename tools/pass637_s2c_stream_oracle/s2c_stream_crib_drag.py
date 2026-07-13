#!/usr/bin/env python3
"""Crib-drag S2C known text over the continuous TCP byte stream.

Output is metadata only: offsets, labels, slot counts, scores, and validation flags.
No raw stream bytes, hashes, derived key bytes, or decoded bytes are written.
"""
from __future__ import annotations
import argparse, csv, json, sys
from bisect import bisect_right
from pathlib import Path

REPO = Path(r"C:\AionTools\aion-agent-bridge")
TOOL = REPO / "tools" / "pass637_s2c_stream_oracle"
PASS636 = REPO / "tools" / "pass636_antigravity_s2c_oracle"
for p in (str(TOOL), str(PASS636), str(REPO)):
    if p not in sys.path:
        sys.path.insert(0, p)

from tcp_reassemble_7785 import build_streams, DEFAULT_PCAP
from s2c_crib_drag_oracle import C2S_ORACLE, LABEL_TO_TEXT, STATIC_KEY
from s2c_keyroll_validate import MOTD_CANDIDATES

BODY_PHASES = [0, 2, 4, 6, 8, 10, 12, 16]
MAX_PER_TYPE = 50000


def kxseq_cribs():
    for _, label, _ in C2S_ORACLE:
        text = LABEL_TO_TEXT[label]
        yield "kxseq", label, text.encode("utf-16le")
        yield "kxseq", label + "_nul", text.encode("utf-16le") + b"\x00\x00"


def motd_cribs():
    for label, crib in MOTD_CANDIDATES:
        if len(crib) >= 8:
            yield "motd_phase5", label, crib


def derive_slots(stream: bytes, off: int, crib: bytes, body_phase: int):
    slots = {}
    conflicts = 0
    for j, plain in enumerate(crib):
        pos = off + j
        phase = (body_phase + j) & 63
        key_slot = phase & 7
        if phase == 0:
            val = stream[pos] ^ plain
        else:
            val = stream[pos] ^ plain ^ STATIC_KEY[phase] ^ stream[pos - 1]
        old = slots.get(key_slot)
        if old is not None and old != val:
            conflicts += 1
        slots[key_slot] = val
    return len(slots), conflicts


def nearest_frame_for_offset(ranges, off: int):
    starts = [int(r["stream_offset_start"]) for r in ranges]
    idx = bisect_right(starts, off) - 1
    if 0 <= idx < len(ranges):
        r = ranges[idx]
        if int(r["stream_offset_start"]) <= off < int(r["stream_offset_end"]):
            return r["frame_number"], int(r["stream_offset_start"]), int(r["stream_offset_end"])
    if idx + 1 < len(ranges):
        r = ranges[idx + 1]
        return r["frame_number"], int(r["stream_offset_start"]), int(r["stream_offset_end"])
    return "", "", ""



def merge_intervals(intervals):
    if not intervals:
        return []
    intervals = sorted(intervals)
    merged = [list(intervals[0])]
    for start, end in intervals[1:]:
        if start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(a, b) for a, b in merged]


def candidate_intervals(ranges, candidate_type: str, stream_len: int):
    intervals = []
    if candidate_type == "motd_phase5":
        for r in ranges:
            if int(r["frame_number"]) < 4200:
                intervals.append((max(1, int(r["stream_offset_start"]) - 64), min(stream_len, int(r["stream_offset_end"]) + 64)))
    else:
        oracle_frames = [4329, 4353, 4360, 4389, 4399, 4402, 4422, 4429, 4435]
        for frame in oracle_frames:
            for r in ranges:
                fn = int(r["frame_number"])
                if frame - 25 <= fn <= frame + 80:
                    intervals.append((max(1, int(r["stream_offset_start"]) - 64), min(stream_len, int(r["stream_offset_end"]) + 64)))
    return merge_intervals(intervals)


def scan_stream(stream: bytes, ranges, cribs, candidate_type: str):
    rows = []
    offsets_tested = 0
    intervals = candidate_intervals(ranges, candidate_type, len(stream))
    for ctype, label, crib in cribs:
        if ctype != candidate_type:
            continue
        if len(crib) > len(stream):
            continue
        for lo, hi in intervals:
            limit = max(lo, hi - len(crib))
            for off in range(lo, limit, 2):
                offsets_tested += 1
                best = None
                for phase in BODY_PHASES:
                    valid, conflicts = derive_slots(stream, off, crib, phase)
                    if conflicts == 0 and valid >= 8:
                        score = valid + min(16, len(crib) // 2)
                        if best is None or score > best[0]:
                            best = (score, phase, valid, conflicts)
                if best:
                    frame, fs, fe = nearest_frame_for_offset(ranges, off)
                    rows.append({
                        "candidate_type": candidate_type,
                        "stream_offset": off,
                        "nearest_frame": frame,
                        "nearest_frame_stream_start": fs,
                        "nearest_frame_stream_end": fe,
                        "label": label,
                        "body_phase": best[1],
                        "slots_recovered": best[2],
                        "consistency_score": best[0],
                        "validated_exact_plaintext": "false",
                        "keyroll_validated": "false",
                        "notes": "stream crib slot consistency only; interval-limited around relevant frames",
                    })
    rows.sort(key=lambda r: (int(r["consistency_score"]), int(r["slots_recovered"]), -int(r["stream_offset"])), reverse=True)
    return rows[:MAX_PER_TYPE], offsets_tested, len(rows)

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", default=str(DEFAULT_PCAP))
    ap.add_argument("--repo-root", default=str(REPO))
    ns = ap.parse_args()
    repo = Path(ns.repo_root)
    built = build_streams(Path(ns.pcap))
    stream = built["streams"]["S2C"]
    ranges = sorted(built["ranges"]["S2C"], key=lambda r: int(r["stream_offset_start"]))
    krows, ktested, ktotal = scan_stream(stream, ranges, list(kxseq_cribs()), "kxseq")
    mrows, mtested, mtotal = scan_stream(stream, ranges, list(motd_cribs()), "motd_phase5")
    rows = krows + mrows
    out = repo / "artifacts" / "pass637_s2c_stream_crib_candidates.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    fields = ["candidate_type", "stream_offset", "nearest_frame", "nearest_frame_stream_start", "nearest_frame_stream_end", "label", "body_phase", "slots_recovered", "consistency_score", "validated_exact_plaintext", "keyroll_validated", "notes"]
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)
    summary = {"s2c_stream_offsets_tested": ktested + mtested, "kxseq_stream_candidates": ktotal, "motd_stream_candidates": mtotal, "written_rows": len(rows)}
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()
