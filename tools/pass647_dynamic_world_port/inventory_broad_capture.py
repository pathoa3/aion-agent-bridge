#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from pcap_dynamic import EUROAION_SERVER_IP, WORLD_PORT_RANGE, canonical_flow_parts, iso_time, parse_pcapng, write_csv

DEFAULT_PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
REPO = Path(__file__).resolve().parents[2]


def confidence_reason(role: str, server_port: int, packets: int, payload_bytes: int, duration: float) -> tuple[str, str]:
    if role == "world_game_candidate" and server_port in WORLD_PORT_RANGE and packets > 1000 and payload_bytes > 100000 and duration > 60:
        return "high", "EuroAion server IP with long-lived high-volume 7770-7799 TCP flow"
    if role == "chat_sidechannel_candidate":
        return "high", "known EuroAion chat-sidechannel port 10242 present"
    if role == "login_candidate":
        return "high", "known login port 2106 present"
    if role == "launcher_or_update_candidate":
        return "medium", "known auxiliary port 11000 present briefly"
    return "low", "not a EuroAion world/chat/login candidate"


def build_inventory(pcap: Path, out: Path) -> dict:
    packets = parse_pcapng(pcap)
    flows = {}
    for pkt in packets:
        server_ip, server_port, client_ip, client_port = canonical_flow_parts(pkt)
        fid = f"{client_ip}:{client_port}<->{server_ip}:{server_port}"
        stats = flows.setdefault(fid, {
            "flow_id": fid, "server_ip": server_ip, "server_port": server_port,
            "client_ip": client_ip, "client_port": client_port, "packets": 0,
            "total_tcp_payload_bytes": 0, "s2c_packets": 0, "c2s_packets": 0,
            "s2c_payload_bytes": 0, "c2s_payload_bytes": 0, "first_ts": pkt.ts,
            "last_ts": pkt.ts, "role_guess": pkt.role_guess,
        })
        stats["packets"] += 1
        stats["total_tcp_payload_bytes"] += pkt.payload_len
        if pkt.direction_guess == "S2C":
            stats["s2c_packets"] += 1
            stats["s2c_payload_bytes"] += pkt.payload_len
        elif pkt.direction_guess == "C2S":
            stats["c2s_packets"] += 1
            stats["c2s_payload_bytes"] += pkt.payload_len
        if pkt.ts is not None:
            stats["first_ts"] = pkt.ts if stats["first_ts"] is None else min(stats["first_ts"], pkt.ts)
            stats["last_ts"] = pkt.ts if stats["last_ts"] is None else max(stats["last_ts"], pkt.ts)
    rows = []
    for s in flows.values():
        duration = 0.0 if s["first_ts"] is None or s["last_ts"] is None else s["last_ts"] - s["first_ts"]
        conf, reason = confidence_reason(s["role_guess"], int(s["server_port"]), s["packets"], s["total_tcp_payload_bytes"], duration)
        rows.append({
            "flow_id": s["flow_id"], "server_ip": s["server_ip"], "server_port": s["server_port"],
            "client_ip": s["client_ip"], "client_port": s["client_port"], "packets": s["packets"],
            "total_tcp_payload_bytes": s["total_tcp_payload_bytes"], "s2c_packets": s["s2c_packets"],
            "c2s_packets": s["c2s_packets"], "s2c_payload_bytes": s["s2c_payload_bytes"],
            "c2s_payload_bytes": s["c2s_payload_bytes"], "first_time": iso_time(s["first_ts"]),
            "last_time": iso_time(s["last_ts"]), "duration_sec": f"{duration:.3f}",
            "role_guess": s["role_guess"], "confidence": conf, "reason": reason,
        })
    rows.sort(key=lambda r: (r["role_guess"], -int(r["total_tcp_payload_bytes"])))
    fields = ["flow_id","server_ip","server_port","client_ip","client_port","packets","total_tcp_payload_bytes","s2c_packets","c2s_packets","s2c_payload_bytes","c2s_payload_bytes","first_time","last_time","duration_sec","role_guess","confidence","reason"]
    write_csv(out, rows, fields)
    return {"flows": len(rows), "tcp_packets": len(packets)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", type=Path, default=DEFAULT_PCAP)
    ap.add_argument("--out", type=Path, default=REPO / "artifacts" / "pass647_broad_flow_inventory.csv")
    ns = ap.parse_args()
    summary = build_inventory(ns.pcap, ns.out)
    print(summary)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
