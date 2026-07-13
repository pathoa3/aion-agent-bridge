#!/usr/bin/env python3
from __future__ import annotations

import csv
import datetime as dt
import ipaddress
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

EUROAION_SERVER_IP = "51.83.147.97"
KNOWN_SERVER_PORTS = {2106, 10242, 11000}
WORLD_PORT_RANGE = range(7770, 7800)

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

    def involves_port(self, port: int) -> bool:
        return self.src_port == port or self.dst_port == port

    @property
    def role_guess(self) -> str:
        return role_guess(self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    @property
    def server_port_guess(self) -> Optional[int]:
        if self.src_ip == EUROAION_SERVER_IP and (self.src_port in KNOWN_SERVER_PORTS or self.src_port in WORLD_PORT_RANGE):
            return self.src_port
        if self.dst_ip == EUROAION_SERVER_IP and (self.dst_port in KNOWN_SERVER_PORTS or self.dst_port in WORLD_PORT_RANGE):
            return self.dst_port
        if self.src_port in (443,):
            return self.src_port
        if self.dst_port in (443,):
            return self.dst_port
        return None

    @property
    def direction_guess(self) -> str:
        port = self.server_port_guess
        if port is None:
            return "unknown"
        if self.src_ip == EUROAION_SERVER_IP and self.src_port == port:
            return "S2C"
        if self.dst_ip == EUROAION_SERVER_IP and self.dst_port == port:
            return "C2S"
        if self.src_port == port:
            return "S2C"
        if self.dst_port == port:
            return "C2S"
        return "unknown"

    @property
    def flow_id(self) -> str:
        server_ip, server_port, client_ip, client_port = canonical_flow_parts(self)
        return f"{client_ip}:{client_port}<->{server_ip}:{server_port}"


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def role_guess(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
    ports = {src_port, dst_port}
    ips = {src_ip, dst_ip}
    if 2106 in ports and EUROAION_SERVER_IP in ips:
        return "login_candidate"
    if 10242 in ports and EUROAION_SERVER_IP in ips:
        return "chat_sidechannel_candidate"
    if 11000 in ports and EUROAION_SERVER_IP in ips:
        return "launcher_or_update_candidate"
    if EUROAION_SERVER_IP in ips and any(p in WORLD_PORT_RANGE for p in ports):
        return "world_game_candidate"
    if 443 in ports:
        return "ignored_external_noise"
    if is_private_ip(src_ip) and is_private_ip(dst_ip):
        return "ignored_local_noise"
    return "ignored_external_noise"


def canonical_flow_parts(pkt: TcpPacket) -> tuple[str, int, str, int]:
    port = pkt.server_port_guess
    if pkt.src_ip == EUROAION_SERVER_IP and port == pkt.src_port:
        return pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port
    if pkt.dst_ip == EUROAION_SERVER_IP and port == pkt.dst_port:
        return pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port
    if pkt.src_port in (443, 2106, 10242, 11000) or pkt.src_port in WORLD_PORT_RANGE:
        return pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port
    return pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port


def _read_options(data: bytes, endian: str) -> Dict[int, List[bytes]]:
    options: Dict[int, List[bytes]] = defaultdict(list)
    off = 0
    while off + 4 <= len(data):
        code, length = struct.unpack_from(endian + "HH", data, off)
        off += 4
        if code == 0:
            break
        value = data[off:off + length]
        options[code].append(value)
        off += length
        off += (-length) % 4
    return options


def _ts_resolution(options: Dict[int, List[bytes]]) -> float:
    vals = options.get(9) or []
    if not vals:
        return 1e-6
    v = vals[0][0]
    if v & 0x80:
        return 2 ** -(v & 0x7F)
    return 10 ** -v


def _parse_tcp(linktype: int, packet_data: bytes) -> Optional[Tuple[str, int, str, int, bytes]]:
    if linktype != 1 or len(packet_data) < 14:
        return None
    off = 14
    ethertype = struct.unpack_from("!H", packet_data, 12)[0]
    while ethertype in (0x8100, 0x88A8) and len(packet_data) >= off + 4:
        ethertype = struct.unpack_from("!H", packet_data, off + 2)[0]
        off += 4
    if ethertype != 0x0800 or len(packet_data) < off + 20:
        return None
    ihl = (packet_data[off] & 0x0F) * 4
    if ihl < 20 or len(packet_data) < off + ihl or packet_data[off + 9] != 6:
        return None
    total_len = struct.unpack_from("!H", packet_data, off + 2)[0]
    ip_end = min(off + total_len, len(packet_data))
    src_ip = str(ipaddress.IPv4Address(packet_data[off + 12:off + 16]))
    dst_ip = str(ipaddress.IPv4Address(packet_data[off + 16:off + 20]))
    tcp_off = off + ihl
    if len(packet_data) < tcp_off + 20:
        return None
    src_port, dst_port = struct.unpack_from("!HH", packet_data, tcp_off)
    data_off = ((packet_data[tcp_off + 12] >> 4) & 0x0F) * 4
    if data_off < 20:
        return None
    payload_off = tcp_off + data_off
    payload = b"" if payload_off > ip_end else packet_data[payload_off:ip_end]
    return src_ip, src_port, dst_ip, dst_port, payload


def parse_pcapng(path: Path) -> List[TcpPacket]:
    data = path.read_bytes()
    packets: List[TcpPacket] = []
    endian = "<"
    interfaces: Dict[int, Tuple[int, float]] = {}
    off = 0
    frame = 0
    while off + 12 <= len(data):
        block_type = struct.unpack_from(endian + "I", data, off)[0]
        block_len = struct.unpack_from(endian + "I", data, off + 4)[0]
        if block_type == 0x0A0D0D0A:
            # Section Header block length is endian-independent enough to retry both.
            le_len = struct.unpack_from("<I", data, off + 4)[0]
            be_len = struct.unpack_from(">I", data, off + 4)[0]
            block_len = le_len if 12 <= le_len <= len(data) - off else be_len
            magic = data[off + 8:off + 12]
            if magic == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif magic == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            interfaces = {}
            block_type = 0x0A0D0D0A
        if block_len < 12 or off + block_len > len(data):
            break
        trailer = struct.unpack_from(endian + "I", data, off + block_len - 4)[0]
        if trailer != block_len:
            off += 4
            continue
        body = data[off + 8:off + block_len - 4]
        if block_type == 0x00000001 and len(body) >= 8:
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            options = _read_options(body[8:], endian)
            interfaces[len(interfaces)] = (linktype, _ts_resolution(options))
        elif block_type == 0x00000006 and len(body) >= 20:
            frame += 1
            iface, ts_high, ts_low, cap_len, _orig_len = struct.unpack_from(endian + "IIIII", body, 0)
            packet_data = body[20:20 + cap_len]
            linktype, ts_res = interfaces.get(iface, (1, 1e-6))
            parsed = _parse_tcp(linktype, packet_data)
            if parsed:
                src_ip, src_port, dst_ip, dst_port, payload = parsed
                ts = ((ts_high << 32) | ts_low) * ts_res
                packets.append(TcpPacket(frame, ts, src_ip, src_port, dst_ip, dst_port, len(payload), payload))
        elif block_type == 0x00000003 and len(body) >= 4:
            frame += 1
            cap_len = struct.unpack_from(endian + "I", body, 0)[0]
            parsed = _parse_tcp(1, body[4:4 + cap_len])
            if parsed:
                src_ip, src_port, dst_ip, dst_port, payload = parsed
                packets.append(TcpPacket(frame, None, src_ip, src_port, dst_ip, dst_port, len(payload), payload))
        off += block_len
    return packets


def iso_time(ts: Optional[float]) -> str:
    if ts is None:
        return ""
    return dt.datetime.fromtimestamp(ts).isoformat(sep=" ", timespec="milliseconds")


def write_csv(path: Path, rows: Iterable[dict], fieldnames: List[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow({name: row.get(name, "") for name in fieldnames})
            count += 1
    return count
