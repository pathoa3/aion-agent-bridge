#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

REPO = Path(r"C:\AionTools\aion-agent-bridge")
TOOL = REPO / "tools" / "pass636_antigravity_s2c_oracle"
for p in (str(TOOL), str(REPO)):
    if p not in sys.path:
        sys.path.insert(0, p)

from s2c_crib_drag_oracle import _parse_pcapng, _extract_tcp  # type: ignore


def read_hints(log_path: Path) -> list[tuple[int | None, str]]:
    if not log_path.exists():
        return []
    text = log_path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        dialect = csv.Sniffer().sniff("\n".join(text.splitlines()[:8]), delimiters=",\t;|")
    except csv.Error:
        dialect = csv.excel
    rows = csv.DictReader(text.splitlines(), dialect=dialect)
    hints: list[tuple[int | None, str]] = []
    for row in rows:
        frame_raw = (row.get("frame_hint") or "").strip()
        label = (row.get("visible_text") or "").strip()
        try:
            frame = int(frame_raw) if frame_raw else None
        except ValueError:
            frame = None
        if label:
            hints.append((frame, label))
    return hints


def label_for_frame(frame: int, hints: list[tuple[int | None, str]], window: int) -> str:
    labels = []
    for hint, label in hints:
        if hint is not None and abs(frame - hint) <= window:
            labels.append(label)
    return ";".join(labels[:3])


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract safe S2C/C2S packet window metadata only.")
    ap.add_argument("pcap_path", type=Path)
    ap.add_argument("known_log_path", type=Path)
    ap.add_argument("--out-csv", type=Path, default=Path("artifacts/pass638_s2c_window_inventory.csv"))
    ap.add_argument("--frame-window", type=int, default=100)
    ns = ap.parse_args()

    hints = read_hints(ns.known_log_path)
    rows: list[dict[str, object]] = []
    first_ts: float | None = None
    for pkt_no, ts, linktype, raw in _parse_pcapng(ns.pcap_path):
        tcp = _extract_tcp(linktype, raw)
        if not tcp or not tcp.get("payload"):
            continue
        if first_ts is None:
            first_ts = ts
        payload_len = len(tcp["payload"])
        direction = tcp.get("direction", "unknown")
        label = label_for_frame(pkt_no, hints, ns.frame_window)
        if direction == "S2C" or label:
            rows.append({
                "frame": pkt_no,
                "direction": direction,
                "payload_len": payload_len,
                "ts_relative": f"{(ts - first_ts):.6f}" if first_ts is not None else "0.000000",
                "near_known_text_hint": str(bool(label)).lower(),
                "candidate_window_label": label,
            })

    ns.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with ns.out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["frame", "direction", "payload_len", "ts_relative", "near_known_text_hint", "candidate_window_label"])
        writer.writeheader()
        writer.writerows(rows)
    print({"rows": len(rows), "out_csv": str(ns.out_csv)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
