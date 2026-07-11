from __future__ import annotations

import csv
import hashlib
import math
import re
import socket
import struct
from pathlib import Path


BRIDGE = Path(r"C:\AionTools\aion-agent-bridge")
PRIVATE = Path(r"C:\AionTools\aion_decoder_agent")
ART = BRIDGE / "artifacts"
INBOX = BRIDGE / "inbox"
EURO = PRIVATE / "inbox" / "euroaion"
CAP = PRIVATE / "inbox" / "captures" / "pass574_chosen_plaintext.pcapng"
ORACLE_LOG = PRIVATE / "inbox" / "captures" / "pass574_known_plaintext_log.txt"

STATIC_KEY = b"nKO/WctQ0AVLbpzfBkS6NevDYT8ourG5CRlmdjyJ72aswx4EPq1UgZhFMXH?3iI9"
ORACLE_MESSAGES = [
    "KX01_A",
    "KX02_AA",
    "KX03_AAA",
    "KX04_AAAA",
    "KX08_AAAAAAAA",
    "KX15_AAAAAAAAAAAAAAA",
    "KX16_AAAAAAAAAAAAAAAA",
    "KX17_AAAAAAAAAAAAAAAAA",
    "KX31_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "KX32_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "KX33_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "KX_REPEAT_AAAAAAAAAAAAAAAA",
    "KX_REPEAT_AAAAAAAAAAAAAAAA",
    "KX_ALT_ABABABABABABABAB",
    "KX_NUM_0123456789",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = 0.0
    for c in counts:
        if c:
            p = c / len(data)
            total -= p * math.log2(p)
    return total


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


def find_all(data: bytes, pat: bytes) -> list[int]:
    out: list[int] = []
    pos = 0
    while True:
        hit = data.find(pat, pos)
        if hit < 0:
            return out
        out.append(hit)
        pos = hit + 1


def ascii_context(data: bytes, off: int, span: int = 96) -> str:
    lo = max(0, off - span // 2)
    hi = min(len(data), off + span // 2)
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data[lo:hi])


def hex_context(data: bytes, off: int, span: int = 96) -> str:
    lo = max(0, off - span // 2)
    hi = min(len(data), off + span // 2)
    return data[lo:hi].hex()


def classify_file(path: Path) -> str:
    rel = str(path).replace("/", "\\").lower()
    name = path.name.lower()
    if "aion4.9" in rel or "gamez" in rel:
        return "Aion4.9_Gamez_public_control"
    if "detiny" in rel or "destiny" in rel:
        return "Destiny_or_comparable_target"
    if "euroaion" in rel and name in {"game.dll", "aion.bin"}:
        return "EuroAion_target_primary"
    if name in {"libeay32.dll", "ssleay32.dll", "zlib1.dll", "version.dll"}:
        return "support_dll"
    if path.suffix.lower() in {".dll", ".bin", ".exe"}:
        return "other_binary"
    return "other_file"


def parse_pe_sections(data: bytes) -> list[dict[str, object]]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return []
    try:
        peoff = struct.unpack_from("<I", data, 0x3C)[0]
        if data[peoff:peoff + 4] != b"PE\0\0":
            return []
        nsec = struct.unpack_from("<H", data, peoff + 6)[0]
        opt_size = struct.unpack_from("<H", data, peoff + 20)[0]
        sec_off = peoff + 24 + opt_size
        out = []
        for i in range(nsec):
            off = sec_off + i * 40
            name = data[off:off + 8].rstrip(b"\0").decode("latin-1", "replace")
            vsize, va, raw_size, raw, _rel, _line, _nr, _nl, flags = struct.unpack_from("<IIIIIIHHI", data, off + 8)
            sec_data = data[raw:min(len(data), raw + raw_size)] if raw and raw < len(data) else b""
            out.append({
                "name": name,
                "va": va,
                "vsize": vsize,
                "raw": raw,
                "raw_size": raw_size,
                "flags": flags,
                "exec": bool(flags & 0x20000000),
                "entropy": entropy(sec_data),
            })
        return out
    except Exception:
        return []


def section_for_offset(sections: list[dict[str, object]], off: int) -> str:
    for s in sections:
        raw = int(s["raw"])
        raw_size = int(s["raw_size"])
        if raw <= off < raw + raw_size:
            return str(s["name"])
    return ""


def parse_oracle_messages() -> list[str]:
    if not ORACLE_LOG.exists():
        return ORACLE_MESSAGES
    msgs: list[str] = []
    for line in ORACLE_LOG.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"\s*\d+\.\s+(.+?)\s*$", line)
        if m:
            msgs.append(m.group(1))
    return msgs or ORACLE_MESSAGES


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
    return {
        "src": f"{src_ip}:{src_port}",
        "dst": f"{dst_ip}:{dst_port}",
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "tcp_header_len": tcp_hlen,
        "payload": pkt[payload_off:payload_end],
    }

