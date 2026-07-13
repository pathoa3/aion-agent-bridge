from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
REPO = THIS_DIR.parents[1]
sys.path.insert(0, str(THIS_DIR))
from pcap_metadata import SERVER_PORTS, iso_time, parse_pcapng, role_for_ports, write_csv

DEFAULT_PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
DEFAULT_LOG = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt")
DEFAULT_ART = REPO / "artifacts"


def read_marker_times(log_path: Path):
    markers = []
    with log_path.open("r", newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            text = (row.get("visible_text") or "").strip()
            if text.startswith("S2C_ORACLE_"):
                markers.append((row.get("timestamp_local", ""), text))
    return markers


def flow_key(pkt):
    a = (pkt.src_ip, pkt.src_port)
    b = (pkt.dst_ip, pkt.dst_port)
    if pkt.src_port in SERVER_PORTS or pkt.dst_port not in SERVER_PORTS:
        return (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
    return (pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port)


def near_marker_label(pkt, marker_times):
    if pkt.ts is None:
        return ""
    # Safe string-only nearest marker flag. The detailed correlation script computes deltas.
    import datetime as dt
    for ts_text, marker in marker_times:
        try:
            ts = dt.datetime.strptime(ts_text, "%Y-%m-%d %H:%M:%S.%f").timestamp()
        except ValueError:
            continue
        if abs(pkt.ts - ts) <= 3:
            return marker
    return ""


def inventory(pcap: Path, log_path: Path, artifacts: Path) -> dict:
    packets = [p for p in parse_pcapng(pcap) if p.server_port in (10242, 2106, 7785)]
    markers = read_marker_times(log_path)
    timeline_rows = []
    flow_stats = {}
    for pkt in packets:
        if pkt.server_port != 10242:
            continue
        timeline_rows.append({
            "frame": pkt.frame,
            "time_local": iso_time(pkt.ts),
            "direction": pkt.direction_guess,
            "src_ip": pkt.src_ip,
            "src_port": pkt.src_port,
            "dst_ip": pkt.dst_ip,
            "dst_port": pkt.dst_port,
            "tcp_len": pkt.payload_len,
            "near_marker": near_marker_label(pkt, markers),
            "role_guess": role_for_ports(pkt.src_port, pkt.dst_port),
        })
    write_csv(artifacts / "pass645_10242_packet_timeline.csv", timeline_rows, [
        "frame", "time_local", "direction", "src_ip", "src_port", "dst_ip", "dst_port", "tcp_len", "near_marker", "role_guess"
    ])

    for pkt in packets:
        key = flow_key(pkt)
        stats = flow_stats.setdefault(key, {
            "flow_id": f"{key[0]}:{key[1]}<->{key[2]}:{key[3]}",
            "server_port": pkt.server_port,
            "role_guess": pkt.role_guess,
            "packets": 0,
            "s2c_packets": 0,
            "c2s_packets": 0,
            "total_tcp_payload_bytes": 0,
            "first_ts": pkt.ts,
            "last_ts": pkt.ts,
        })
        stats["packets"] += 1
        stats["total_tcp_payload_bytes"] += pkt.payload_len
        if pkt.direction_guess == "S2C":
            stats["s2c_packets"] += 1
        elif pkt.direction_guess == "C2S":
            stats["c2s_packets"] += 1
        if pkt.ts is not None:
            stats["first_ts"] = pkt.ts if stats["first_ts"] is None else min(stats["first_ts"], pkt.ts)
            stats["last_ts"] = pkt.ts if stats["last_ts"] is None else max(stats["last_ts"], pkt.ts)
    flow_rows = []
    for stats in flow_stats.values():
        flow_rows.append({
            "flow_id": stats["flow_id"],
            "server_port": stats["server_port"],
            "role_guess": stats["role_guess"],
            "packets": stats["packets"],
            "s2c_packets": stats["s2c_packets"],
            "c2s_packets": stats["c2s_packets"],
            "total_tcp_payload_bytes": stats["total_tcp_payload_bytes"],
            "first_time": iso_time(stats["first_ts"]),
            "last_time": iso_time(stats["last_ts"]),
        })
    flow_rows.sort(key=lambda r: (int(r["server_port"]), r["flow_id"]))
    write_csv(artifacts / "pass645_10242_flow_inventory.csv", flow_rows, [
        "flow_id", "server_port", "role_guess", "packets", "s2c_packets", "c2s_packets", "total_tcp_payload_bytes", "first_time", "last_time"
    ])
    return {"timeline_rows": len(timeline_rows), "flow_rows": len(flow_rows)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Inventory the fresh 10242 oracle capture using safe metadata only.")
    parser.add_argument("--pcap", type=Path, default=DEFAULT_PCAP)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--artifacts", type=Path, default=DEFAULT_ART)
    args = parser.parse_args()
    summary = inventory(args.pcap, args.log, args.artifacts)
    print("pass645_10242_inventory " + " ".join(f"{k}={v}" for k, v in summary.items()))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

