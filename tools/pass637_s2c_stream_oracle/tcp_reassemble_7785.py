#!/usr/bin/env python3
"""Strict TCP reassembly for the Pass637 7785 world flow.

Artifacts are metadata only. Raw stream bytes are kept in memory for downstream
analysis but are never written to committed files.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import struct
from dataclasses import dataclass
from pathlib import Path

CLIENT_IP = "192.168.178.127"
CLIENT_PORT = 58361
SERVER_IP = "54.37.197.248"
SERVER_PORT = 7785
DEFAULT_PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\startup_world_open_kxseq.pcapng")
DEFAULT_REPO = Path(r"C:\AionTools\aion-agent-bridge")

@dataclass
class Segment:
    frame: int
    direction: str
    seq: int
    payload: bytes
    ts: float


def parse_pcapng(path: Path):
    data = path.read_bytes()
    off = 0
    endian = "<"
    linktypes: dict[int, int] = {}
    iface = 0
    frame_no = 0
    while off + 12 <= len(data):
        block_type_le, block_len_le = struct.unpack_from("<II", data, off)
        if block_len_le < 12 or off + block_len_le > len(data):
            break
        block = data[off:off + block_len_le]
        if block_type_le == 0x0A0D0D0A:
            bom = struct.unpack_from("<I", block, 8)[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
        elif block_type_le == 0x00000001:
            linktype = struct.unpack_from(endian + "H", block, 8)[0]
            linktypes[iface] = linktype
            iface += 1
        elif block_type_le == 0x00000006:
            if len(block) >= 32:
                interface_id, tsh, tsl, caplen, origlen = struct.unpack_from(endian + "IIIII", block, 8)
                pkt_off = 28
                raw = block[pkt_off:pkt_off + caplen]
                frame_no += 1
                ts = float((tsh << 32) + tsl)
                yield frame_no, ts, linktypes.get(interface_id, 1), raw
        off += block_len_le


def tcp_from_ethernet(raw: bytes):
    if len(raw) < 14:
        return None
    eth_type = struct.unpack_from("!H", raw, 12)[0]
    ip_off = 14
    if eth_type == 0x8100 and len(raw) >= 18:
        eth_type = struct.unpack_from("!H", raw, 16)[0]
        ip_off = 18
    if eth_type != 0x0800 or len(raw) < ip_off + 20:
        return None
    first = raw[ip_off]
    version = first >> 4
    ihl = (first & 0x0F) * 4
    if version != 4 or ihl < 20 or len(raw) < ip_off + ihl:
        return None
    proto = raw[ip_off + 9]
    if proto != 6:
        return None
    total_len = struct.unpack_from("!H", raw, ip_off + 2)[0]
    src_ip = str(ipaddress.IPv4Address(raw[ip_off + 12:ip_off + 16]))
    dst_ip = str(ipaddress.IPv4Address(raw[ip_off + 16:ip_off + 20]))
    tcp_off = ip_off + ihl
    if len(raw) < tcp_off + 20:
        return None
    src_port, dst_port = struct.unpack_from("!HH", raw, tcp_off)
    seq = struct.unpack_from("!I", raw, tcp_off + 4)[0]
    tcp_hlen = (raw[tcp_off + 12] >> 4) * 4
    if tcp_hlen < 20:
        return None
    payload_start = tcp_off + tcp_hlen
    payload_end = min(ip_off + total_len, len(raw))
    if payload_start > payload_end:
        return None
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "payload": raw[payload_start:payload_end],
    }


def collect_segments(pcap: Path) -> list[Segment]:
    segments: list[Segment] = []
    first_ts = None
    for frame, ts, linktype, raw in parse_pcapng(pcap):
        if linktype != 1:
            continue
        tcp = tcp_from_ethernet(raw)
        if not tcp or not tcp["payload"]:
            continue
        direction = None
        if (tcp["src_ip"], tcp["src_port"], tcp["dst_ip"], tcp["dst_port"]) == (CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT):
            direction = "C2S"
        elif (tcp["src_ip"], tcp["src_port"], tcp["dst_ip"], tcp["dst_port"]) == (SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT):
            direction = "S2C"
        if not direction:
            continue
        if first_ts is None:
            first_ts = ts
        segments.append(Segment(frame=frame, direction=direction, seq=tcp["seq"], payload=tcp["payload"], ts=ts - first_ts))
    return segments


def reassemble_direction(segments: list[Segment], direction: str):
    segs = sorted([s for s in segments if s.direction == direction], key=lambda s: (s.seq, s.frame))
    if not segs:
        return b"", []
    base = min(s.seq for s in segs)
    stream = bytearray()
    ranges = []
    for s in segs:
        start = s.seq - base
        end = start + len(s.payload)
        if start > len(stream):
            stream.extend(b"\x00" * (start - len(stream)))
        append_start = max(0, len(stream) - start)
        if append_start < len(s.payload):
            stream.extend(s.payload[append_start:])
        ranges.append({
            "direction": direction,
            "stream_offset_start": start,
            "stream_offset_end": end,
            "frame_number": s.frame,
            "tcp_payload_len": len(s.payload),
            "tcp_seq_delta": start,
            "ts_relative": f"{s.ts:.3f}",
            "overlap_or_retx": str(append_start > 0).lower(),
            "gap_before": str(start > len(stream)).lower(),
        })
    return bytes(stream), ranges


def build_streams(pcap: Path = DEFAULT_PCAP):
    segments = collect_segments(pcap)
    c2s_stream, c2s_ranges = reassemble_direction(segments, "C2S")
    s2c_stream, s2c_ranges = reassemble_direction(segments, "S2C")
    return {
        "segments": segments,
        "streams": {"C2S": c2s_stream, "S2C": s2c_stream},
        "ranges": {"C2S": c2s_ranges, "S2C": s2c_ranges},
    }


def write_inventory(repo: Path, built) -> None:
    out = repo / "artifacts" / "pass637_s2c_stream_inventory.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    fields = ["direction", "stream_offset_start", "stream_offset_end", "frame_number", "tcp_payload_len", "tcp_seq_delta", "ts_relative", "overlap_or_retx", "gap_before"]
    rows = built["ranges"]["C2S"] + built["ranges"]["S2C"]
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in sorted(rows, key=lambda x: (x["direction"], int(x["stream_offset_start"]))):
            w.writerow(r)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", default=str(DEFAULT_PCAP))
    ap.add_argument("--repo-root", default=str(DEFAULT_REPO))
    ns = ap.parse_args()
    built = build_streams(Path(ns.pcap))
    write_inventory(Path(ns.repo_root), built)
    print(json.dumps({
        "c2s_len": len(built["streams"]["C2S"]),
        "s2c_len": len(built["streams"]["S2C"]),
        "c2s_segments": len(built["ranges"]["C2S"]),
        "s2c_segments": len(built["ranges"]["S2C"]),
    }, indent=2))

if __name__ == "__main__":
    main()
