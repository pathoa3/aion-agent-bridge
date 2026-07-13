from __future__ import annotations

import csv
import datetime as dt
import ipaddress
import struct
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

SERVER_PORTS = {7785: "game_world_candidate", 10242: "chat_sidechannel_candidate", 2106: "login_candidate"}

@dataclass
class TcpPacket:
    frame: int
    ts: Optional[float]
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload_len: int
    payload: bytes

    @property
    def flow_id(self) -> str:
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}"

    @property
    def role_guess(self) -> str:
        return SERVER_PORTS.get(self.src_port) or SERVER_PORTS.get(self.dst_port) or "ignored"

    @property
    def server_port(self) -> Optional[int]:
        if self.src_port in SERVER_PORTS:
            return self.src_port
        if self.dst_port in SERVER_PORTS:
            return self.dst_port
        return None

    @property
    def direction_guess(self) -> str:
        if self.src_port in SERVER_PORTS:
            return "S2C"
        if self.dst_port in SERVER_PORTS:
            return "C2S"
        return "unknown"


def _read_options(data: bytes, endian: str) -> Dict[int, List[bytes]]:
    options: Dict[int, List[bytes]] = defaultdict(list)
    offset = 0
    while offset + 4 <= len(data):
        code, length = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        if code == 0:
            break
        value = data[offset:offset + length]
        options[code].append(value)
        offset += length
        offset += (-length) % 4
    return options


def _ts_resolution(options: Dict[int, List[bytes]]) -> float:
    values = options.get(9) or []
    if not values:
        return 1e-6
    value = values[0][0]
    if value & 0x80:
        return 2 ** -(value & 0x7F)
    return 10 ** -value


def _parse_tcp_from_link(linktype: int, packet_data: bytes) -> Optional[Tuple[str, int, str, int, bytes]]:
    if linktype != 1 or len(packet_data) < 14:
        return None
    offset = 12
    ethertype = struct.unpack_from("!H", packet_data, offset)[0]
    offset = 14
    while ethertype in (0x8100, 0x88A8) and len(packet_data) >= offset + 4:
        ethertype = struct.unpack_from("!H", packet_data, offset + 2)[0]
        offset += 4
    if ethertype != 0x0800 or len(packet_data) < offset + 20:
        return None
    first = packet_data[offset]
    ihl = (first & 0x0F) * 4
    if ihl < 20 or len(packet_data) < offset + ihl:
        return None
    proto = packet_data[offset + 9]
    if proto != 6:
        return None
    total_len = struct.unpack_from("!H", packet_data, offset + 2)[0]
    src_ip = str(ipaddress.IPv4Address(packet_data[offset + 12:offset + 16]))
    dst_ip = str(ipaddress.IPv4Address(packet_data[offset + 16:offset + 20]))
    tcp_offset = offset + ihl
    if len(packet_data) < tcp_offset + 20:
        return None
    src_port, dst_port = struct.unpack_from("!HH", packet_data, tcp_offset)
    tcp_header_len = ((packet_data[tcp_offset + 12] >> 4) & 0x0F) * 4
    if tcp_header_len < 20:
        return None
    payload_offset = tcp_offset + tcp_header_len
    ip_payload_end = offset + min(total_len, len(packet_data) - offset)
    if payload_offset > ip_payload_end:
        payload = b""
    else:
        payload = packet_data[payload_offset:ip_payload_end]
    return src_ip, src_port, dst_ip, dst_port, payload


def parse_pcapng(path: Path) -> List[TcpPacket]:
    data = path.read_bytes()
    packets: List[TcpPacket] = []
    interfaces: Dict[int, Tuple[int, float]] = {}
    endian = "<"
    offset = 0
    frame = 0
    while offset + 12 <= len(data):
        block_type_le, block_len_le = struct.unpack_from("<II", data, offset)
        block_type = block_type_le
        block_len = block_len_le
        if block_len < 12 or offset + block_len > len(data):
            break
        block = data[offset:offset + block_len]
        body = block[8:-4]
        if block_type == 0x0A0D0D0A:
            magic = block[8:12]
            if magic == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif magic == b"\x1a\x2b\x3c\x4d":
                endian = ">"
        elif block_type == 0x00000001 and len(body) >= 8:
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            options = _read_options(body[8:], endian)
            interfaces[len(interfaces)] = (linktype, _ts_resolution(options))
        elif block_type == 0x00000006 and len(body) >= 20:
            frame += 1
            interface_id, ts_high, ts_low, cap_len, _orig_len = struct.unpack_from(endian + "IIIII", body, 0)
            packet_data = body[20:20 + cap_len]
            linktype, ts_res = interfaces.get(interface_id, (1, 1e-6))
            parsed = _parse_tcp_from_link(linktype, packet_data)
            if parsed is not None:
                src_ip, src_port, dst_ip, dst_port, payload = parsed
                ts = ((ts_high << 32) | ts_low) * ts_res
                packets.append(TcpPacket(frame, ts, src_ip, src_port, dst_ip, dst_port, len(payload), payload))
        elif block_type == 0x00000003 and len(body) >= 4:
            frame += 1
            cap_len = struct.unpack_from(endian + "I", body, 0)[0]
            packet_data = body[4:4 + cap_len]
            parsed = _parse_tcp_from_link(1, packet_data)
            if parsed is not None:
                src_ip, src_port, dst_ip, dst_port, payload = parsed
                packets.append(TcpPacket(frame, None, src_ip, src_port, dst_ip, dst_port, len(payload), payload))
        offset += block_len
    return packets


def iso_time(ts: Optional[float]) -> str:
    if ts is None:
        return ""
    return dt.datetime.fromtimestamp(ts).isoformat(sep=" ", timespec="milliseconds")


def role_for_ports(src_port: int, dst_port: int) -> str:
    return SERVER_PORTS.get(src_port) or SERVER_PORTS.get(dst_port) or "ignored"


def write_csv(path: Path, rows: Iterable[dict], fieldnames: List[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})
            count += 1
    return count
