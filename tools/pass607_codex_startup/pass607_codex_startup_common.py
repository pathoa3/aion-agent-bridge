from __future__ import annotations

import csv
import hashlib
import json
import re
import socket
import struct
from pathlib import Path


BRIDGE = Path(r"C:\AionTools\aion-agent-bridge")
PRIVATE = Path(r"C:\AionTools\aion_decoder_agent")
ART = BRIDGE / "artifacts"
INBOX = BRIDGE / "inbox"
TOOLS = BRIDGE / "tools" / "pass607_codex_startup"
STARTUP_PCAP = PRIVATE / "inbox" / "captures" / "startup_login_world_entry.pcapng"
STARTUP_LOG = PRIVATE / "inbox" / "captures" / "known_plaintext_log.txt"
PASS574_PCAP = PRIVATE / "inbox" / "captures" / "pass574_chosen_plaintext.pcapng"
PASS574_LOG = PRIVATE / "inbox" / "captures" / "pass574_known_plaintext_log.txt"

PACKET9740_HEX = "f27bc160cff2a4c0ebfdc3"
SMKEY_PREFIX = bytes.fromhex("0b00f9015606fe")
MASK7 = bytes.fromhex("f97b386199f45a")
SEED = bytes.fromhex("3990c5a2")
EXPECTED_SMKEY = SMKEY_PREFIX + SEED
STATIC_KEY = b"nKO/WctQ0AVLbpzfBkS6NevDYT8ourG5CRlmdjyJ72aswx4EPq1UgZhFMXH?3iI9"


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = list(rows[0].keys()) if rows else ["status"]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def json_write(path: Path, obj: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def spaced_hex(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def parse_log_messages(path: Path) -> list[str]:
    if not path.exists():
        return []
    out: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"\s*\d+\.\s+(.+?)\s*$", line)
        if m:
            out.append(m.group(1).strip())
            continue
        m = re.search(r"\|\s*/say\s*\|\s*([A-Za-z0-9_]+)", line)
        if m:
            out.append(m.group(1).strip())
    return out


def parse_pcapng_packets(path: Path):
    data = path.read_bytes()
    off = 0
    endian = "<"
    ifaces: dict[int, int] = {}
    iface_index = 0
    packet_no = 0
    while off + 12 <= len(data):
        block_type, total_len = struct.unpack_from(endian + "II", data, off)
        if total_len < 12 or off + total_len > len(data):
            break
        body_off = off + 8
        if block_type == 0x0A0D0D0A:
            bom = struct.unpack_from("<I", data, off + 8)[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
        elif block_type == 1:
            linktype = struct.unpack_from(endian + "H", data, body_off)[0]
            ifaces[iface_index] = linktype
            iface_index += 1
        elif block_type == 6:
            iface_id, ts_hi, ts_lo, cap_len, _orig_len = struct.unpack_from(endian + "IIIII", data, body_off)
            pkt = data[body_off + 20:body_off + 20 + cap_len]
            packet_no += 1
            ts = (((ts_hi << 32) | ts_lo) / 1_000_000.0)
            yield packet_no, ts, ifaces.get(iface_id, -1), pkt
        elif block_type == 3:
            cap_len = struct.unpack_from(endian + "I", data, body_off + 12)[0]
            pkt = data[body_off + 16:body_off + 16 + cap_len]
            packet_no += 1
            yield packet_no, float(packet_no), ifaces.get(0, -1), pkt
        off += total_len


def tcp_payload(linktype: int, pkt: bytes) -> dict[str, object] | None:
    if linktype == 1 and len(pkt) >= 14:
        if struct.unpack_from("!H", pkt, 12)[0] != 0x0800:
            return None
        ip_off = 14
    elif len(pkt) >= 20 and (pkt[0] >> 4) == 4:
        ip_off = 0
    else:
        return None
    if len(pkt) < ip_off + 20:
        return None
    ihl = (pkt[ip_off] & 0x0F) * 4
    if pkt[ip_off + 9] != 6:
        return None
    total_len = struct.unpack_from("!H", pkt, ip_off + 2)[0]
    src_ip = socket.inet_ntoa(pkt[ip_off + 12:ip_off + 16])
    dst_ip = socket.inet_ntoa(pkt[ip_off + 16:ip_off + 20])
    tcp_off = ip_off + ihl
    if len(pkt) < tcp_off + 20:
        return None
    src_port, dst_port, seq, ack = struct.unpack_from("!HHII", pkt, tcp_off)
    tcp_hlen = (pkt[tcp_off + 12] >> 4) * 4
    payload_off = tcp_off + tcp_hlen
    payload_end = min(len(pkt), ip_off + total_len)
    if payload_end < payload_off:
        return None
    payload = pkt[payload_off:payload_end]
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "src": f"{src_ip}:{src_port}",
        "dst": f"{dst_ip}:{dst_port}",
        "seq": seq,
        "ack": ack,
        "tcp_header_len": tcp_hlen,
        "payload": payload,
    }


def flow_key(p: dict[str, object]) -> str:
    a = (str(p["src_ip"]), int(p["src_port"]))
    b = (str(p["dst_ip"]), int(p["dst_port"]))
    lo, hi = sorted([a, b])
    return f"{lo[0]}:{lo[1]}<->{hi[0]}:{hi[1]}"


def direction_for(p: dict[str, object]) -> str:
    if int(p["src_port"]) == 59085 or int(p["dst_port"]) == 7785:
        return "C2S"
    if int(p["dst_port"]) == 59085 or int(p["src_port"]) == 7785:
        return "S2C"
    return "unknown"


def tcp_payload_rows(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    stream_ids: dict[str, int] = {}
    for packet_no, ts, linktype, pkt in parse_pcapng_packets(path):
        p = tcp_payload(linktype, pkt)
        if not p:
            continue
        fk = flow_key(p)
        if fk not in stream_ids:
            stream_ids[fk] = len(stream_ids)
        payload = p["payload"]
        rows.append({
            "packet_no": packet_no,
            "timestamp": ts,
            "tcp_stream": stream_ids[fk],
            "flow": fk,
            "direction": direction_for(p),
            "src": p["src"],
            "dst": p["dst"],
            "src_port": p["src_port"],
            "dst_port": p["dst_port"],
            "seq": p["seq"],
            "ack": p["ack"],
            "tcp_header_len": p["tcp_header_len"],
            "payload": payload,
            "payload_len": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest() if payload else "",
        })
    return rows


def xor_repeat(data: bytes, mask: bytes) -> bytes:
    return bytes(b ^ mask[i % len(mask)] for i, b in enumerate(data))


def xor_first_then_tail(data: bytes, mask: bytes) -> bytes:
    return bytes((b ^ mask[i]) if i < len(mask) else b for i, b in enumerate(data))


def public_xorpass(data: bytes, key8: bytes, offset: int = 0, include_prev: bool = True, update_size_before: bool = False) -> bytes:
    if len(key8) != 8:
        raise ValueError("key8 must be 8 bytes")
    out = bytearray(data)
    key64 = int.from_bytes(key8, "little")
    if update_size_before:
        key64 = (key64 + max(0, len(data) - offset)) & 0xFFFFFFFFFFFFFFFF
    key = key64.to_bytes(8, "little")
    if offset >= len(out):
        return bytes(out)
    prev = out[offset]
    out[offset] ^= key[0]
    for pos in range(offset + 1, len(out)):
        i = pos - offset
        cur = out[pos]
        mask = STATIC_KEY[i & 0x3F] ^ key[i & 0x7]
        if include_prev:
            mask ^= prev
        out[pos] ^= mask
        prev = cur
    return bytes(out)


def validate_plain(decoded: bytes, markers: list[str]) -> dict[str, object]:
    matches = [m for m in markers if m.encode("utf-16le") in decoded or m.encode("ascii") in decoded]
    length_le = int.from_bytes(decoded[:2], "little") if len(decoded) >= 2 else -1
    length_sane = 2 <= length_le <= len(decoded) + 64
    opcode = decoded[2] if len(decoded) >= 3 else -1
    complement_ok = False
    if len(decoded) >= 4:
        complement_ok = ((decoded[2] ^ decoded[3]) == 0xFF)
    printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in decoded[:96])
    return {
        "length_le": length_le,
        "length_sane": "yes" if length_sane else "no",
        "opcode_hex": f"{opcode:02X}" if opcode >= 0 else "",
        "opcode_complement_ok": "yes" if complement_ok else "no",
        "utf16le_or_ascii_containment": "yes" if matches else "no",
        "matched_messages": "|".join(matches),
        "decoded_prefix_hex": decoded[:96].hex(),
        "decoded_prefix_ascii": printable,
    }
