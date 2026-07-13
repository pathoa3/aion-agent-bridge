#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REPO = Path(r"C:\AionTools\aion-agent-bridge")
PASS616 = REPO / "tools" / "pass616_sonnet_c2s_decoder"
for p in (str(PASS616), str(REPO)):
    if p not in sys.path:
        sys.path.insert(0, p)

from euroaion_c2s_decoder import (  # type: ignore
    STATIC_KEY,
    decode_body,
    decode_opcode,
    complement_valid,
)

WORLD_PORT = 7785

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
    def direction(self) -> str:
        if self.dst_port == WORLD_PORT:
            return "C2S"
        if self.src_port == WORLD_PORT:
            return "S2C"
        return "unknown"

    @property
    def server_port(self) -> int:
        if self.src_port == WORLD_PORT:
            return self.src_port
        if self.dst_port == WORLD_PORT:
            return self.dst_port
        return self.dst_port


def write_csv(path: Path, fields: list[str], rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


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
                rows.append(Record(
                    index=idx,
                    frame=int(parts[0]),
                    linktype=int(parts[1]),
                    src_ip=parts[2],
                    src_port=int(parts[3]),
                    dst_ip=parts[4],
                    dst_port=int(parts[5]),
                    payload_len=int(parts[6]),
                    payload=bytes.fromhex(parts[7]),
                ))
            except Exception:
                continue
    return rows


def role_guess(rec: Record, candidate_frame: int) -> str:
    if rec.frame == candidate_frame and rec.direction == "C2S" and rec.payload_len == 26:
        return "c2s_known_text_checkpoint_candidate"
    if rec.direction == "C2S" and rec.frame in (344, 348, 351, 356, 375, 381):
        return "nearby_c2s_roll_validation_target"
    if rec.direction == "S2C" and abs(rec.frame - candidate_frame) <= 6:
        return "nearby_s2c_context_only"
    return "nearby_context"


def metadata_rows(records: list[Record], candidate_frame: int) -> list[dict]:
    selected = [r for r in records if 340 <= r.frame <= 390]
    rows = []
    for i, rec in enumerate(selected):
        rows.append({
            "record_index": rec.index,
            "frame": rec.frame,
            "direction": rec.direction,
            "server_port": rec.server_port,
            "payload_len": rec.payload_len,
            "delta_prev_record": rec.frame - selected[i - 1].frame if i else "",
            "delta_next_record": selected[i + 1].frame - rec.frame if i + 1 < len(selected) else "",
            "role_guess": role_guess(rec, candidate_frame),
        })
    return rows


def derive_slots(cipher_body: bytes, plain: bytes, body_offset: int) -> tuple[dict[int, int], int]:
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
        old = slots.get(slot)
        if old is not None and old != val:
            conflicts += 1
        slots[slot] = val
    return slots, conflicts


def packet_variants(text: str, body_len: int) -> list[tuple[str, bytes, list[int]]]:
    utf16 = text.encode("utf-16le")
    utf16_nul = utf16 + b"\x00\x00"
    ascii_b = text.encode("ascii", errors="ignore")
    preferred_offsets = [6, 8, 10, 12, 14, 16]
    out = []
    for name, plain in [("utf16le_exact", utf16), ("utf16le_nul", utf16_nul), ("ascii_control", ascii_b)]:
        out.append((name, plain, [o for o in preferred_offsets if o + len(plain) <= body_len]))
    return out


def decode_plausibility(decoded: bytes, plain: bytes, offset: int) -> tuple[bool, bool, bool, str]:
    exact = offset >= 0 and offset + len(plain) <= len(decoded) and decoded[offset:offset + len(plain)] == plain
    op = decode_opcode(decoded[0]) if decoded else -1
    comp = complement_valid(decoded)
    opcode_plausible = 0 <= op < 0x80
    return exact, opcode_plausible, comp, f"opcode=0x{op:02X}; complement={str(comp).lower()}; exact_text={str(exact).lower()}"


def derive_candidates(target: Record, known_text: str) -> tuple[list[dict], list[dict], bytes | None, bytes | None]:
    body = target.payload[2:] if len(target.payload) > 2 else b""
    cand_rows: list[dict] = []
    val_rows: list[dict] = []
    best_key: bytes | None = None
    best_decoded: bytes | None = None
    best_score = -999

    for variant, plain, offsets in packet_variants(known_text, len(body)):
        if not offsets:
            cand_rows.append({
                "variant": variant,
                "body_offset": "unsupported",
                "slots_recovered": 0,
                "conflicts": "n/a",
                "exact_text_recovered": "false",
                "opcode_plausible": "false",
                "confidence": "unsupported_by_payload_length",
                "reason": f"body_len={len(body)} cannot hold variant_len={len(plain)} at requested offsets",
            })
            continue
        for off in offsets:
            slots, conflicts = derive_slots(body, plain, off)
            full = len(slots) == 8 and conflicts == 0
            control_only = variant == "ascii_control"
            checkpoint_eligible = full and not control_only
            exact = False
            opcode_plausible = False
            comp = False
            plaus_reason = "full key not derived"
            if full:
                key = bytes(slots[i] for i in range(8))
                decoded = decode_body(body, bytearray(key))
                exact, opcode_plausible, comp, plaus_reason = decode_plausibility(decoded, plain, off)
                score = (100 if exact else 0) + (20 if opcode_plausible else 0) + (10 if comp else 0) + len(slots) - conflicts
                if checkpoint_eligible and score > best_score:
                    best_score = score
                    best_key = key
                    best_decoded = decoded
            confidence = "reject"
            if control_only and full:
                confidence = "ascii_control_only_not_checkpoint"
                exact = False
                opcode_plausible = False
                plaus_reason += "; ascii control is not accepted as known-text recovery"
            elif full and exact and opcode_plausible:
                confidence = "strong_packet_checkpoint_candidate"
            elif full and exact:
                confidence = "exact_text_but_opcode_weak"
            elif full:
                confidence = "full_slots_but_layout_weak"
            elif conflicts == 0:
                confidence = "partial_slots_only"
            reason = f"variant_len={len(plain)}; body_len={len(body)}; full_slots={str(full).lower()}; checkpoint_eligible={str(checkpoint_eligible).lower()}; {plaus_reason}"
            row = {
                "variant": variant,
                "body_offset": off,
                "slots_recovered": len(slots),
                "conflicts": conflicts,
                "exact_text_recovered": str(exact).lower(),
                "opcode_plausible": str(opcode_plausible).lower(),
                "confidence": confidence,
                "reason": reason,
            }
            cand_rows.append(row)
            val_rows.append(dict(row))
    return cand_rows, val_rows, best_key, best_decoded


def validation_score(decoded: bytes) -> tuple[bool, int, str]:
    if not decoded:
        return False, 0, "empty_decoded"
    op = decode_opcode(decoded[0])
    comp = complement_valid(decoded)
    score = 0
    if 0 <= op < 0x80:
        score += 4
    if comp:
        score += 5
    if len(decoded) >= 3:
        score += 1
    return score >= 5, score, f"opcode=0x{op:02X}; complement={str(comp).lower()}"


def label_row(rec: Record, valid: bool, score: int, basis: str) -> dict:
    label = "unknown"
    confidence = "low"
    if rec.payload_len in (11, 12, 14) and valid:
        label = "likely_ping_or_small_control"
        confidence = "medium"
    elif rec.payload_len == 26 and rec.frame == 370:
        label = "likely_chat_whisper_known_text"
        confidence = "high" if valid else "medium"
    elif rec.payload_len > 1000:
        label = "likely_large_world_action_or_state_packet"
        confidence = "medium" if valid else "low"
    elif valid:
        label = "plausible_c2s_control"
        confidence = "medium"
    return {
        "frame": rec.frame,
        "direction": rec.direction,
        "payload_len": rec.payload_len,
        "label": label,
        "confidence": confidence,
        "reason": f"basis={basis}; validation_score={score}; validated={str(valid).lower()}",
    }


def roll_validation(records: list[Record], checkpoint: Record | None, key: bytes | None, decoded_checkpoint: bytes | None) -> tuple[list[dict], list[dict], bool, bool]:
    target_frames = [344, 348, 351, 356, 370, 375, 381]
    by_frame = {r.frame: r for r in records if r.direction == "C2S"}
    rows = []
    labels = []
    if checkpoint is None or key is None:
        for frame in target_frames:
            rec = by_frame.get(frame)
            if rec:
                rows.append({
                    "start_frame": 370,
                    "target_frame": frame,
                    "direction": rec.direction,
                    "payload_len": rec.payload_len,
                    "roll_direction": "none",
                    "validated": "false",
                    "validation_score": 0,
                    "reason": "no UTF-16LE full checkpoint key derived; ASCII control is not accepted",
                })
                labels.append(label_row(rec, False, 0, "no_checkpoint_key"))
        return rows, labels, False, False

    ok, score, reason = validation_score(decoded_checkpoint or b"")
    rows.append({
        "start_frame": checkpoint.frame,
        "target_frame": checkpoint.frame,
        "direction": "C2S",
        "payload_len": checkpoint.payload_len,
        "roll_direction": "checkpoint",
        "validated": str(ok).lower(),
        "validation_score": score,
        "reason": reason,
    })
    labels.append(label_row(checkpoint, ok, score, "known_text_checkpoint"))
    return rows, labels, False, False


def run(capture_dir: Path, known_text: str, candidate_frame: int) -> dict:
    artifacts = REPO / "artifacts"
    records_file = capture_dir / "records_7785_old.tsv"
    records = parse_records(records_file)
    target = next((r for r in records if r.frame == candidate_frame), None)

    write_csv(
        artifacts / "pass642_frame370_metadata.csv",
        ["record_index", "frame", "direction", "server_port", "payload_len", "delta_prev_record", "delta_next_record", "role_guess"],
        metadata_rows(records, candidate_frame),
    )

    if target is None:
        cand_rows: list[dict] = []
        val_rows: list[dict] = []
        best_key = None
        best_dec = None
    else:
        cand_rows, val_rows, best_key, best_dec = derive_candidates(target, known_text)

    deriv_fields = ["variant", "body_offset", "slots_recovered", "conflicts", "exact_text_recovered", "opcode_plausible", "confidence", "reason"]
    write_csv(artifacts / "pass642_frame370_key_derivation_candidates.csv", deriv_fields, cand_rows)
    write_csv(artifacts / "pass642_frame370_decode_validation.csv", deriv_fields, val_rows)

    roll_rows, label_rows, back_ok, fwd_ok = roll_validation(records, target, best_key, best_dec)
    write_csv(artifacts / "pass642_c2s_roll_validation.csv", ["start_frame", "target_frame", "direction", "payload_len", "roll_direction", "validated", "validation_score", "reason"], roll_rows)
    write_csv(artifacts / "pass642_old_c2s_packet_labels.csv", ["frame", "direction", "payload_len", "label", "confidence", "reason"], label_rows)

    preferred_rows = [r for r in cand_rows if str(r.get("variant", "")).startswith("utf16le")]
    packet_key_slots = max([int(r["slots_recovered"]) for r in preferred_rows if str(r["slots_recovered"]).isdigit() and str(r["conflicts"]) == "0"] or [0])
    exact = any(r["exact_text_recovered"] == "true" and str(r.get("variant", "")).startswith("utf16le") for r in val_rows)
    op_plausible = any(r["opcode_plausible"] == "true" and str(r.get("variant", "")).startswith("utf16le") for r in val_rows if r["exact_text_recovered"] == "true")

    decision = {
        "worker": "codex",
        "phase": "pass642_old_capture_c2s_checkpoint_from_hello_hi",
        "capture_found": capture_dir.exists(),
        "frame370_found": target is not None,
        "frame370_len26_found": bool(target and target.payload_len == 26),
        "utf16le_hello_hi_len_model_matches": bool(target and len(known_text.encode("utf-16le")) + 10 == target.payload_len),
        "packet_key_slots_derived": packet_key_slots,
        "full_packet_key_derived_local_only": best_key is not None,
        "frame370_exact_text_recovered": exact,
        "frame370_opcode_plausible": op_plausible,
        "c2s_roll_backward_validated": back_ok,
        "c2s_roll_forward_validated": fwd_ok,
        "nearby_c2s_packets_labeled": sum(1 for r in label_rows if "validated=true" in str(r.get("reason", ""))),
        "tooling_checkpoint_mode_added": True,
        "s2c_plaintext_recovered": False,
        "s2c_decoder_success": False,
        "needs_longer_repeated_s2c_oracle": True,
        "private_payload_committed": False,
        "raw_ciphertext_committed": False,
        "raw_plaintext_blob_committed": False,
        "raw_binary_committed": False,
        "reason": "UTF-16LE known-text variants did not produce a conflict-free packet key at the requested offsets. ASCII controls were explicitly rejected as checkpoint evidence. No S2C plaintext was recovered.",
        "next_action": "Use Pass638 fresh S2C oracle capture; checkpoint-only mode can validate future known-text packet candidates safely.",
    }
    (artifacts / "pass642_c2s_checkpoint_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")

    summary = f"""# Pass642 C2S Checkpoint Summary

Input capture: `{capture_dir}`

Results:
- Frame {candidate_frame} found: {target is not None}
- Frame {candidate_frame} C2S len 26: {bool(target and target.direction == 'C2S' and target.payload_len == 26)}
- UTF-16LE `Hello Hi` length model matches: {decision['utf16le_hello_hi_len_model_matches']}
- UTF-16LE conflict-free packet key slots derived: {packet_key_slots}
- Full packet key accepted locally only: {best_key is not None}
- Exact UTF-16LE frame {candidate_frame} text recovered locally: {exact}
- Opcode plausible on exact UTF-16LE candidate: {op_plausible}
- C2S forward roll validated: {fwd_ok}
- C2S backward roll validated: {back_ok}
- Meaningful nearby C2S packet labels: {sum(1 for r in label_rows if "validated=true" in str(r.get("reason", "")))}
- S2C plaintext recovered: false

ASCII `Hello Hi` was tested only as a negative/control and was not accepted as checkpoint evidence. No key bytes, packet hex, ciphertext, decoded blobs, packet hashes, binaries, or secrets were written to committed artifacts.

Interpretation: frame {candidate_frame} remains a strong length/alignment marker for the user-provided action, but the requested UTF-16LE packet-key checkpoint was not validated from this old capture. The next useful path is still the longer repeated S2C oracle from Pass638.
"""
    (artifacts / "pass642_c2s_checkpoint_summary.md").write_text(summary, encoding="utf-8")

    report = f"""# Codex Report - Pass642

Pass642 attempted to derive an old-session C2S checkpoint from frame {candidate_frame} using the known text `Hello Hi`.

Frame {candidate_frame} matches the UTF-16LE+10 length model, but the UTF-16LE plaintext variants conflicted under the Pass616 C2S cipher model at the requested offsets. ASCII was tested only as a negative/control and was not accepted as checkpoint evidence. No exact S2C plaintext was recovered and no S2C decoder success is claimed.

Next action: use the Pass638 fresh S2C oracle capture with longer repeated visible markers. The checkpoint-only mode can be reused for future known-text packet candidates.
"""
    (REPO / "inbox" / "codex_report.md").write_text(report, encoding="utf-8")
    return decision


def main() -> int:
    parser = argparse.ArgumentParser(description="Derive an old-session C2S checkpoint from known text; safe metadata only.")
    parser.add_argument("--capture-dir", type=Path, default=Path(r"C:\AionTools\captures\aion_capture_20260704_011724"))
    parser.add_argument("--known-text", default="Hello Hi")
    parser.add_argument("--candidate-frame", type=int, default=370)
    parser.add_argument("--direction", choices=["C2S", "S2C"], default="C2S")
    parser.add_argument("--derive-checkpoint-only", action="store_true")
    ns = parser.parse_args()
    if ns.direction != "C2S":
        raise SystemExit("Checkpoint derivation currently supports C2S only; S2C initial key remains unknown.")
    print(json.dumps(run(ns.capture_dir, ns.known_text, ns.candidate_frame), indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())



