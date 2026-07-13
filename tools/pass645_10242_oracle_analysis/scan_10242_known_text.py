from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
REPO = THIS_DIR.parents[1]
sys.path.insert(0, str(THIS_DIR))
from pcap_metadata import iso_time, parse_pcapng, write_csv

DEFAULT_PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
DEFAULT_LOG = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt")
DEFAULT_OUT = REPO / "artifacts" / "pass645_10242_literal_text_hits.csv"

LFG_LINES = [
    "[3.LFG] Jaq: <Recruit Alliance>SWB FFA Canon Sinway Pull Dog Pod Killer",
    "[3.LFG] Rorai: <Recruit Alliance>IS/KATA x2 DPS/IDK/TANK/HEAL",
    "[3.LFG] Hexane: <Recruit Alliance>IS/Kata x2 GG DPS/IDK Gear check)",
    "[3.LFG] Lsyra: <Recruit Alliance>IS/Kata x2 GG DPS/IDK Gear check)",
    "[3.LFG] Phyruonno: <Recruit Group>RUNA BONUS NEED GG CLERIC (WE HAVE KEYS)",
    "[3.LFG] Sosomi: <Recruit Group>",
    "Seahlt: TestSay",
]


def read_texts(log_path: Path):
    texts = []
    with log_path.open("r", newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            text = (row.get("visible_text") or "").strip()
            if text.startswith("S2C_ORACLE_"):
                texts.append((text, "marker_exact", text))
                texts.append(("::Spirips Whispers: " + text, "whisper_visible_form", text))
                texts.append(("Spirips: " + text, "group_visible_form", text))
            elif text == "TestSay":
                texts.append((text, "weak_testsay", text))
                texts.append(("Seahlt: TestSay", "weak_testsay_visible_form", text))
    for line in LFG_LINES:
        texts.append((line, "lfg_screenshot_line", line))
    # De-duplicate while keeping order.
    seen = set()
    deduped = []
    for visible, scope, label in texts:
        key = (visible, scope, label)
        if key not in seen:
            seen.add(key)
            deduped.append((visible, scope, label))
    return deduped


def encodings(text: str):
    return [("ascii", text.encode("ascii", errors="ignore")), ("utf-16le", text.encode("utf-16le", errors="ignore"))]


def scan(pcap: Path, log_path: Path, out_path: Path) -> dict:
    texts = read_texts(log_path)
    packets = [p for p in parse_pcapng(pcap) if p.server_port == 10242 and p.payload_len > 0]
    rows = []
    for pkt in packets:
        for text, scope, label in texts:
            for encoding, needle in encodings(text):
                if needle and pkt.payload.find(needle) >= 0:
                    rows.append({
                        "frame": pkt.frame,
                        "time_local": iso_time(pkt.ts),
                        "direction": pkt.direction_guess,
                        "tcp_len": pkt.payload_len,
                        "text_label": label,
                        "encoding": encoding,
                        "match_scope": scope,
                        "confidence": "high_literal_match",
                        "notes": "literal bytes found in 10242 payload in memory; payload not written",
                    })
    write_csv(out_path, rows, ["frame", "time_local", "direction", "tcp_len", "text_label", "encoding", "match_scope", "confidence", "notes"])
    return {"hits": len(rows), "packets_scanned": len(packets), "texts_tested": len(texts)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan 10242 payloads for known visible chat text without writing payload bytes.")
    parser.add_argument("--pcap", type=Path, default=DEFAULT_PCAP)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    summary = scan(args.pcap, args.log, args.out)
    print("pass645_10242_literal_scan " + " ".join(f"{k}={v}" for k, v in summary.items()))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

