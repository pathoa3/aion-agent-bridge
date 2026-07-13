#!/usr/bin/env python3
"""Validate Pass637 C2S reassembled stream against known KXSEQ oracle frames."""
from __future__ import annotations
import argparse, csv, sys
from pathlib import Path

REPO = Path(r"C:\AionTools\aion-agent-bridge")
TOOL = REPO / "tools" / "pass637_s2c_stream_oracle"
PASS636 = REPO / "tools" / "pass636_antigravity_s2c_oracle"
for p in (str(TOOL), str(PASS636), str(REPO)):
    if p not in sys.path:
        sys.path.insert(0, p)

from tcp_reassemble_7785 import build_streams, DEFAULT_PCAP
from s2c_crib_drag_oracle import C2S_ORACLE, LABEL_TO_TEXT


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", default=str(DEFAULT_PCAP))
    ap.add_argument("--repo-root", default=str(REPO))
    ns = ap.parse_args()
    repo = Path(ns.repo_root)
    built = build_streams(Path(ns.pcap))
    by_frame = {int(r["frame_number"]): r for r in built["ranges"]["C2S"]}
    rows = []
    all_ok = True
    for frame, label, spaced in C2S_ORACLE:
        text = LABEL_TO_TEXT[label]
        expected_raw_len = len(text.encode("utf-16le")) + 10
        r = by_frame.get(frame)
        found = r is not None
        payload_len = int(r["tcp_payload_len"]) if r else 0
        len_ok = payload_len == expected_raw_len
        all_ok = all_ok and found and len_ok
        rows.append({
            "oracle_frame": frame,
            "label": label,
            "stream_offset_start": r["stream_offset_start"] if r else "",
            "stream_offset_end": r["stream_offset_end"] if r else "",
            "tcp_payload_len": payload_len if r else "",
            "expected_utf16le_len": len(text.encode("utf-16le")),
            "expected_raw_len_utf16_plus_10": expected_raw_len,
            "frame_found_in_stream": str(found).lower(),
            "length_model_valid": str(len_ok).lower(),
            "stream_alignment_valid": str(found and len_ok).lower(),
        })
    out = repo / "artifacts" / "pass637_c2s_stream_alignment.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        fields = list(rows[0].keys())
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader(); w.writerows(rows)
    print({"c2s_stream_alignment_validated": all_ok, "rows": len(rows)})

if __name__ == "__main__":
    main()
