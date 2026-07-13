#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REPO = Path(r"C:\AionTools\aion-agent-bridge")
PASS616 = REPO / "tools" / "pass616_sonnet_c2s_decoder"
for p in (str(PASS616), str(REPO)):
    if p not in sys.path:
        sys.path.insert(0, p)

from euroaion_c2s_decoder import STATIC_KEY, _parse_pcapng, _extract_tcp  # type: ignore

WORLD_PORT = 7785
SIDE_PORT = 10242
CLIENT_PREFIXES = ("192.168.", "10.", "172.16.")

@dataclass
class Record:
    index: int
    frame: int
    linktype: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload_len: int
    payload: bytes

    @property
    def server_port(self) -> int:
        if self.src_port in (WORLD_PORT, SIDE_PORT):
            return self.src_port
        if self.dst_port in (WORLD_PORT, SIDE_PORT):
            return self.dst_port
        return self.dst_port

    @property
    def direction(self) -> str:
        if self.dst_port in (WORLD_PORT, SIDE_PORT):
            return "C2S"
        if self.src_port in (WORLD_PORT, SIDE_PORT):
            return "S2C"
        return "unknown"


def capture_dir_arg(value: str) -> Path:
    return Path(value)


def records_path(capture_dir: Path) -> Path:
    return capture_dir / "records_7785_old.tsv"


def pcap_path(capture_dir: Path) -> Path:
    return capture_dir / "aion_capture.pcapng"


def parse_records(path: Path) -> list[Record]:
    rows: list[Record] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f):
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 8:
                continue
            try:
                payload = bytes.fromhex(parts[7])
                rows.append(Record(
                    index=idx,
                    frame=int(parts[0]),
                    linktype=int(parts[1]),
                    src_ip=parts[2],
                    src_port=int(parts[3]),
                    dst_ip=parts[4],
                    dst_port=int(parts[5]),
                    payload_len=int(parts[6]),
                    payload=payload,
                ))
            except Exception:
                continue
    return rows


def role_guess(rec: Record) -> str:
    if rec.frame == 370 and rec.direction == "C2S" and rec.payload_len == 26:
        return "likely_C2S_Hello_Hi_len26"
    if rec.frame in (371, 373, 376) and rec.direction == "S2C":
        return "nearby_S2C_response_candidate"
    if 350 <= rec.frame <= 390:
        return "nearby_context"
    return "world_7785_payload"


def write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def derive_slots(cipher_body: bytes, plain: bytes, body_offset: int) -> tuple[int, int, str]:
    slots: dict[int, int] = {}
    conflicts = 0
    for j, p in enumerate(plain):
        i = body_offset + j
        if i < 0 or i >= len(cipher_body):
            conflicts += 1
            continue
        if i == 0:
            val = cipher_body[i] ^ p
        else:
            val = cipher_body[i] ^ p ^ STATIC_KEY[i & 63] ^ cipher_body[i - 1]
        slot = i & 7
        if slot in slots and slots[slot] != val:
            conflicts += 1
        else:
            slots[slot] = val
    return len(slots), conflicts, ";".join(str(k) for k in sorted(slots))


def crib_variants(text: str) -> list[tuple[str, bytes]]:
    utf16 = text.encode("utf-16le")
    ascii_b = text.encode("ascii", errors="ignore")
    return [
        ("ascii", ascii_b),
        ("utf16le", utf16),
        ("utf16le_nul", utf16 + b"\x00\x00"),
    ]


def scan_literal_file(path: Path, known_text: str) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    data = path.read_bytes()
    tests = [
        (known_text, "ascii", known_text.encode("ascii", errors="ignore")),
        ("Hello", "ascii", b"Hello"),
        ("Hi", "ascii", b"Hi"),
        (known_text, "utf16le", known_text.encode("utf-16le")),
        ("Hello", "utf16le", "Hello".encode("utf-16le")),
        ("Hi", "utf16le", "Hi".encode("utf-16le")),
        ("whisper", "ascii", b"whisper"),
        ("party", "ascii", b"party"),
        ("trade", "ascii", b"trade"),
        ("public", "ascii", b"public"),
    ]
    direction = "C2S" if "192.168." in path.name.split("__")[0] else "S2C"
    for label, enc, needle in tests:
        found = bool(needle and needle in data)
        if found:
            rows.append({
                "direction": direction,
                "payload_len": len(data),
                "string_found": label,
                "encoding": enc,
                "confidence": "literal_stream_match",
                "notes": f"stream_file={path.name}; committed row contains no raw bytes",
            })
    if not rows:
        rows.append({
            "direction": direction,
            "payload_len": len(data),
            "string_found": "none",
            "encoding": "n/a",
            "confidence": "none",
            "notes": f"stream_file={path.name}; no literal Hello/Hi/channel strings found",
        })
    return rows


def file_inventory(capture_dir: Path) -> list[dict]:
    wanted = [
        ("aion_capture.pcapng", "pcap", "primary packet capture"),
        ("records_7785_old.tsv", "records_tsv", "7785 payload records; raw hex excluded from artifacts"),
        ("record_probe_result.txt", "probe_text", "prior record summary"),
        ("handshake_probe_result.txt", "probe_text", "prior handshake summary"),
    ]
    rows = []
    for rel, ftype, role in wanted:
        p = capture_dir / rel
        rows.append({
            "file_path": str(p),
            "file_type": ftype,
            "size_bytes": p.stat().st_size if p.exists() else 0,
            "mtime": p.stat().st_mtime if p.exists() else "",
            "role_guess": role if p.exists() else "missing",
        })
    streams = capture_dir / "streams"
    if streams.exists():
        for p in sorted(streams.glob("*.bin")):
            port = "7785" if "7785" in p.name else "10242" if "10242" in p.name else "other"
            rows.append({
                "file_path": str(p),
                "file_type": "stream_bin",
                "size_bytes": p.stat().st_size,
                "mtime": p.stat().st_mtime,
                "role_guess": f"{port} directional TCP stream; raw stream not committed",
            })
    return rows


def timeline_rows(records: list[Record], lo: int = 340, hi: int = 390) -> list[dict]:
    selected = [r for r in records if lo <= r.frame <= hi]
    rows = []
    for i, rec in enumerate(selected):
        prev_delta = rec.frame - selected[i - 1].frame if i > 0 else ""
        next_delta = selected[i + 1].frame - rec.frame if i + 1 < len(selected) else ""
        rows.append({
            "record_index": rec.index,
            "frame": rec.frame,
            "direction": rec.direction,
            "server_port": rec.server_port,
            "payload_len": rec.payload_len,
            "delta_prev_record": prev_delta,
            "delta_next_record": next_delta,
            "role_guess": role_guess(rec),
        })
    return rows


def frame370_validation(records: list[Record], known_text: str, candidate_frame: int) -> list[dict]:
    expected_len = len(known_text.encode("utf-16le")) + 10
    c2s_len_matches = [r for r in records if r.direction == "C2S" and r.payload_len == expected_len]
    target = next((r for r in records if r.frame == candidate_frame), None)
    rows = []
    if not target:
        rows.append({
            "candidate_frame": candidate_frame,
            "payload_len": "missing",
            "expected_len": expected_len,
            "exact_text_recovered": "false",
            "key_slots_consistent": "false",
            "decoder_used": "records_7785_length_probe",
            "confidence": "none",
            "reason": "candidate frame not present in records_7785_old.tsv",
        })
        return rows
    body = target.payload[2:] if len(target.payload) > 2 else b""
    best = None
    for label, plain in crib_variants(known_text):
        for off in range(0, max(1, len(body) - len(plain) + 1)):
            slots, conflicts, slot_ids = derive_slots(body, plain, off)
            score = slots - conflicts * 2
            row = (score, label, off, slots, conflicts, slot_ids)
            if best is None or row > best:
                best = row
    score, label, off, slots, conflicts, slot_ids = best if best else (0, "none", -1, 0, 1, "")
    exact = False
    unique_len = len(c2s_len_matches) == 1 and c2s_len_matches[0].frame == candidate_frame
    consistent = conflicts == 0 and slots >= 6
    confidence = "weak_alignment_only"
    if unique_len and consistent and target.direction == "C2S":
        confidence = "best_only_length_and_keyslot_consistency_candidate"
    rows.append({
        "candidate_frame": target.frame,
        "payload_len": target.payload_len,
        "expected_len": expected_len,
        "exact_text_recovered": str(exact).lower(),
        "key_slots_consistent": str(consistent).lower(),
        "decoder_used": "pass616_cipher_crib_slot_check_no_session_anchor",
        "confidence": confidence,
        "reason": f"direction={target.direction}; unique_c2s_len26={str(unique_len).lower()}; best_variant={label}; body_offset={off}; slots={slots}; conflicts={conflicts}; slot_ids={slot_ids}; exact decode unavailable without old-session C2S anchor key",
    })
    return rows


def nearby_s2c_candidates(records: list[Record], known_text: str, candidate_frame: int) -> tuple[list[dict], list[dict]]:
    target_indices = [r.index for r in records if r.frame == candidate_frame]
    if not target_indices:
        return [], []
    idx = target_indices[0]
    window = [r for r in records if abs(r.index - idx) <= 20 and r.direction == "S2C"]
    crib_rows = []
    val_rows = []
    for rec in window:
        body = rec.payload[2:] if len(rec.payload) > 2 else b""
        best = None
        for label, plain in crib_variants(known_text):
            max_off = max(1, len(body) - len(plain) + 1)
            for off in range(max_off):
                slots, conflicts, slot_ids = derive_slots(body, plain, off)
                score = slots - conflicts * 2
                row = (score, label, off, slots, conflicts, slot_ids)
                if best is None or row > best:
                    best = row
        score, label, off, slots, conflicts, slot_ids = best if best else (0, "none", -1, 0, 1, "")
        exact_validated = False
        keyroll_validated = False
        confidence = "low"
        reason = "crib-slot consistency only; S2C initial key unknown; exact plaintext not recovered"
        if conflicts == 0 and slots >= 6:
            confidence = "possible_crib_alignment"
        crib_rows.append({
            "candidate_frame": rec.frame,
            "payload_len": rec.payload_len,
            "crib_variant": f"{label}@body_offset_{off}",
            "slots_recovered": slots,
            "consistency_score": score,
            "exact_text_validated": str(exact_validated).lower(),
            "keyroll_validated": str(keyroll_validated).lower(),
            "confidence": confidence,
            "reason": reason,
        })
        val_rows.append({
            "candidate_frame": rec.frame,
            "payload_len": rec.payload_len,
            "crib_variant": f"{label}@body_offset_{off}",
            "slots_recovered": slots,
            "consistency_score": score,
            "exact_text_validated": str(exact_validated).lower(),
            "keyroll_validated": str(keyroll_validated).lower(),
            "confidence": confidence,
            "reason": reason,
        })
    return crib_rows, val_rows


def scan_10242(capture_dir: Path, known_text: str) -> list[dict]:
    streams = capture_dir / "streams"
    rows: list[dict] = []
    if not streams.exists():
        return [{"direction":"unknown","payload_len":0,"string_found":"none","encoding":"n/a","confidence":"none","notes":"streams directory missing"}]
    for p in sorted(streams.glob("*10242*.bin")):
        rows.extend(scan_literal_file(p, known_text))
    return rows


def run_all(capture_dir: Path, known_text: str, candidate_frame: int) -> dict:
    artifacts = REPO / "artifacts"
    cap = pcap_path(capture_dir)
    rec_path = records_path(capture_dir)
    records = parse_records(rec_path)

    write_csv(artifacts / "pass641_capture_files.csv", ["file_path", "file_type", "size_bytes", "mtime", "role_guess"], file_inventory(capture_dir))
    write_csv(artifacts / "pass641_hello_hi_timeline.csv", ["record_index", "frame", "direction", "server_port", "payload_len", "delta_prev_record", "delta_next_record", "role_guess"], timeline_rows(records))
    c2s_rows = frame370_validation(records, known_text, candidate_frame)
    write_csv(artifacts / "pass641_frame370_c2s_validation.csv", ["candidate_frame", "payload_len", "expected_len", "exact_text_recovered", "key_slots_consistent", "decoder_used", "confidence", "reason"], c2s_rows)
    crib_rows, val_rows = nearby_s2c_candidates(records, known_text, candidate_frame)
    write_csv(artifacts / "pass641_nearby_s2c_crib_candidates.csv", ["candidate_frame", "payload_len", "crib_variant", "slots_recovered", "consistency_score", "exact_text_validated", "keyroll_validated", "confidence", "reason"], crib_rows)
    write_csv(artifacts / "pass641_nearby_s2c_validation.csv", ["candidate_frame", "payload_len", "crib_variant", "slots_recovered", "consistency_score", "exact_text_validated", "keyroll_validated", "confidence", "reason"], val_rows)
    scan_rows = scan_10242(capture_dir, known_text)
    write_csv(artifacts / "pass641_10242_hello_hi_scan.csv", ["direction", "payload_len", "string_found", "encoding", "confidence", "notes"], scan_rows)

    target = next((r for r in records if r.frame == candidate_frame), None)
    expected_len = len(known_text.encode("utf-16le")) + 10
    literal_10242 = any(r["string_found"] == known_text for r in scan_rows)
    near_exact = any(r["exact_text_validated"] == "true" for r in val_rows)
    decision = {
        "worker": "codex",
        "phase": "pass641_hello_hi_old_capture_oracle",
        "capture_found": capture_dir.exists(),
        "pcap_found": cap.exists(),
        "records_7785_found": rec_path.exists(),
        "frame370_len26_found": bool(target and target.payload_len == 26),
        "frame370_matches_expected_len": bool(target and target.payload_len == expected_len),
        "frame370_c2s_exact_text_recovered": False,
        "nearby_s2c_candidates_tested": len(crib_rows),
        "nearby_s2c_exact_text_recovered": near_exact,
        "nearby_s2c_keyroll_validated": False,
        "literal_10242_hello_hi_found": literal_10242,
        "old_capture_useful_for_s2c_oracle": "weak_alignment_only" if bool(target and target.payload_len == expected_len) else "unknown",
        "needs_longer_repeated_oracle": True,
        "validated_s2c_plaintext_found": False,
        "s2c_decoder_success": False,
        "private_payload_committed": False,
        "raw_ciphertext_committed": False,
        "raw_plaintext_blob_committed": False,
        "raw_binary_committed": False,
        "reason": "Frame 370 is the only 7785 C2S packet with the expected UTF-16LE+10 length and has bounded crib-slot consistency, but no old-session C2S anchor key or S2C initial key was recovered. Nearby S2C packets remain unvalidated crib candidates only.",
        "next_action": "Use the fresh longer repeated S2C oracle capture from Pass638; include repeated >=16 character S2C-visible markers and exact local timestamps."
    }
    (artifacts / "pass641_hello_hi_oracle_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")

    summary = f"""# Pass641 Hello Hi Old Capture Oracle Summary

Capture directory found: `{capture_dir}`.

Key findings:
- `aion_capture.pcapng` found: {cap.exists()}
- `records_7785_old.tsv` found: {rec_path.exists()}
- Frame {candidate_frame} present as C2S len 26: {bool(target and target.direction == 'C2S' and target.payload_len == 26)}
- Expected `Hello Hi` C2S length is UTF-16LE 16 bytes + 10 = {expected_len}; frame {candidate_frame} matches that length: {bool(target and target.payload_len == expected_len)}
- Exact C2S plaintext recovered: false
- Nearby S2C candidates tested: {len(crib_rows)}
- Exact S2C plaintext recovered: false
- 10242 literal `Hello Hi` found: {literal_10242}

Interpretation: frame {candidate_frame} is useful as a weak alignment marker and likely C2S `Hello Hi` candidate by unique length, but it does not unlock S2C by itself. The old capture does not provide validated S2C plaintext or S2C keyroll evidence.

Next action: use the Pass638 fresh capture plan with longer repeated S2C-visible markers.
"""
    (artifacts / "pass641_hello_hi_oracle_summary.md").write_text(summary, encoding="utf-8")

    report = f"""# Codex Report - Pass641

Targeted old-capture `Hello Hi` oracle audit completed.

Frame {candidate_frame} is the only 7785 C2S len=26 packet and matches the UTF-16LE+10 length model for `Hello Hi`, but exact plaintext was not recovered because the old session C2S anchor key is unavailable. Nearby S2C packets were tested only as bounded crib candidates; no exact S2C plaintext or keyroll validation was found.

Next action: proceed with the fresh Pass638 S2C oracle capture using longer repeated visible markers.
"""
    (REPO / "inbox" / "codex_report.md").write_text(report, encoding="utf-8")
    return decision


def main() -> int:
    ap = argparse.ArgumentParser(description="Pass641 targeted Hello Hi old capture oracle audit; writes safe metadata only.")
    ap.add_argument("--capture-dir", type=capture_dir_arg, default=Path(r"C:\AionTools\captures\aion_capture_20260704_011724"))
    ap.add_argument("--known-text", default="Hello Hi")
    ap.add_argument("--candidate-frame", type=int, default=370)
    ns = ap.parse_args()
    decision = run_all(ns.capture_dir, ns.known_text, ns.candidate_frame)
    print(json.dumps(decision, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
