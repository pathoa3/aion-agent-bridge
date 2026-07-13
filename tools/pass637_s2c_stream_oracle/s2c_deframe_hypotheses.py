#!/usr/bin/env python3
"""Evaluate safe S2C deframe hypotheses over the reassembled stream."""
from __future__ import annotations
import argparse, csv, json, sys
from pathlib import Path

REPO = Path(r"C:\AionTools\aion-agent-bridge")
TOOL = REPO / "tools" / "pass637_s2c_stream_oracle"
for p in (str(TOOL), str(REPO)):
    if p not in sys.path:
        sys.path.insert(0, p)

from tcp_reassemble_7785 import build_streams, DEFAULT_PCAP

KNOWN_SMALL_S2C = [4094, 4101, 4119, 4122, 4283, 4285, 4293, 4318, 4332, 4354, 4361, 4390]
BODY_START_OFFSETS = [0, 2, 4, 6, 8, 10, 12, 16]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", default=str(DEFAULT_PCAP))
    ap.add_argument("--repo-root", default=str(REPO))
    ns = ap.parse_args()
    repo = Path(ns.repo_root)
    built = build_streams(Path(ns.pcap))
    stream = built["streams"]["S2C"]
    ranges = {int(r["frame_number"]): r for r in built["ranges"]["S2C"]}
    frame_starts = {int(r["stream_offset_start"]): int(r["frame_number"]) for r in built["ranges"]["S2C"]}
    frame_ends = {int(r["stream_offset_end"]): int(r["frame_number"]) for r in built["ranges"]["S2C"]}
    rows = []
    for frame in KNOWN_SMALL_S2C:
        r = ranges.get(frame)
        if not r:
            rows.append({"frame": frame, "frame_present": "false", "stream_offset": "", "tcp_payload_len": "", "body_start_delta": "", "raw_len_word": "", "len_word_plausible": "false", "candidate_packet_end": "", "end_aligns_frame_boundary": "false", "start_aligns_known_frame": "false", "hypothesis_score": 0, "notes": "frame not present in S2C stream"})
            continue
        base = int(r["stream_offset_start"])
        plen = int(r["tcp_payload_len"])
        for delta in BODY_START_OFFSETS:
            start = base + delta
            if start + 2 > len(stream):
                continue
            raw_len = int.from_bytes(stream[start:start+2], "little")
            plausible = 2 <= raw_len <= 4096
            end = start + raw_len
            end_align = end in frame_starts or end in frame_ends
            score = (2 if plausible else 0) + (3 if end_align else 0) + (1 if delta in (0, 2) else 0)
            rows.append({
                "frame": frame,
                "frame_present": "true",
                "stream_offset": start,
                "tcp_payload_len": plen,
                "body_start_delta": delta,
                "raw_len_word": raw_len,
                "len_word_plausible": str(plausible).lower(),
                "candidate_packet_end": end if plausible else "",
                "end_aligns_frame_boundary": str(end_align).lower(),
                "start_aligns_known_frame": str(delta == 0).lower(),
                "hypothesis_score": score,
                "notes": "masked/unmasked length hypothesis metadata only",
            })
    rows.sort(key=lambda r: (int(r["hypothesis_score"]), int(r["frame"])) if r["hypothesis_score"] != "" else (0, int(r["frame"])), reverse=True)
    out = repo / "artifacts" / "pass637_s2c_deframe_hypotheses.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    fields = ["frame", "frame_present", "stream_offset", "tcp_payload_len", "body_start_delta", "raw_len_word", "len_word_plausible", "candidate_packet_end", "end_aligns_frame_boundary", "start_aligns_known_frame", "hypothesis_score", "notes"]
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)
    found = any(str(r["len_word_plausible"]) == "true" and str(r["end_aligns_frame_boundary"]) == "true" for r in rows)
    print(json.dumps({"rows": len(rows), "s2c_deframe_hypothesis_found": found}, indent=2))

if __name__ == "__main__":
    main()
