from __future__ import annotations

import argparse
import csv
import datetime as dt
import sys
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
REPO = THIS_DIR.parents[1]
sys.path.insert(0, str(THIS_DIR))
sys.path.insert(0, str(REPO / "tools" / "pass638_after_capture"))
from pcap_metadata import iso_time, parse_pcapng, write_csv
from validate_known_plaintext_log import classify_row

DEFAULT_PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
DEFAULT_LOG = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt")
DEFAULT_OUT = REPO / "artifacts" / "pass645_10242_marker_correlation.csv"


def parse_local_ts(value: str):
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return dt.datetime.strptime(value.strip(), fmt).timestamp()
        except ValueError:
            continue
    return None


def read_markers(log_path: Path):
    markers = []
    with log_path.open("r", newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            row_class, usable, _warning = classify_row(row.get("direction", ""), row.get("visible_text", ""), row.get("notes", ""))
            if usable:
                markers.append({
                    "marker_text": row.get("visible_text", ""),
                    "marker_notes": row.get("notes", ""),
                    "marker_time_text": row.get("timestamp_local", ""),
                    "marker_ts": parse_local_ts(row.get("timestamp_local", "")),
                })
    return markers


def nearest(packets, marker_ts, max_delta):
    if marker_ts is None:
        return None
    candidates = [p for p in packets if p.ts is not None and abs(p.ts - marker_ts) <= max_delta]
    if not candidates:
        return None
    return min(candidates, key=lambda p: abs(p.ts - marker_ts))


def nearest_any(packets, marker_ts):
    if marker_ts is None or not packets:
        return packets[0] if packets else None
    candidates = [p for p in packets if p.ts is not None]
    if not candidates:
        return packets[0]
    return min(candidates, key=lambda p: abs(p.ts - marker_ts))


def delta_ms(pkt, marker_ts):
    if pkt is None or pkt.ts is None or marker_ts is None:
        return ""
    return int(round((pkt.ts - marker_ts) * 1000))


def correlate(pcap: Path, log_path: Path, out_path: Path) -> dict:
    markers = read_markers(log_path)
    packets = [p for p in parse_pcapng(pcap) if p.server_port == 10242 and p.payload_len > 0]
    s2c = [p for p in packets if p.direction_guess == "S2C"]
    c2s = [p for p in packets if p.direction_guess == "C2S"]
    rows = []
    for marker in markers:
        ts = marker["marker_ts"]
        s_near = nearest(s2c, ts, 3.0)
        c_near = nearest(c2s, ts, 3.0)
        confidence = "exact_window_3s"
        reason = "nearest packets found within +/-3 seconds"
        if s_near is None and c_near is None:
            s_near = nearest(s2c, ts, 30.0)
            c_near = nearest(c2s, ts, 30.0)
            confidence = "fallback_window_30s"
            reason = "no packets in +/-3 seconds; used +/-30 seconds"
        if s_near is None and c_near is None:
            s_near = nearest_any(s2c, ts)
            c_near = nearest_any(c2s, ts)
            confidence = "whole_flow_fallback"
            reason = "no timestamp-window packets; nearest from whole 10242 flow"
        rows.append({
            "marker_text": marker["marker_text"],
            "marker_notes": marker["marker_notes"],
            "marker_time": marker["marker_time_text"],
            "nearest_s2c_frame": s_near.frame if s_near else "",
            "nearest_s2c_time": iso_time(s_near.ts) if s_near else "",
            "delta_ms": delta_ms(s_near, ts),
            "s2c_len": s_near.payload_len if s_near else "",
            "nearest_c2s_frame": c_near.frame if c_near else "",
            "nearest_c2s_time": iso_time(c_near.ts) if c_near else "",
            "c2s_delta_ms": delta_ms(c_near, ts),
            "c2s_len": c_near.payload_len if c_near else "",
            "confidence": confidence,
            "reason": reason,
        })
    write_csv(out_path, rows, [
        "marker_text", "marker_notes", "marker_time", "nearest_s2c_frame", "nearest_s2c_time", "delta_ms", "s2c_len", "nearest_c2s_frame", "nearest_c2s_time", "c2s_delta_ms", "c2s_len", "confidence", "reason"
    ])
    return {"markers": len(markers), "correlations": len(rows)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Correlate known S2C oracle marker timestamps with nearby 10242 packets.")
    parser.add_argument("--pcap", type=Path, default=DEFAULT_PCAP)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    summary = correlate(args.pcap, args.log, args.out)
    print("pass645_10242_marker_correlation " + " ".join(f"{k}={v}" for k, v in summary.items()))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

