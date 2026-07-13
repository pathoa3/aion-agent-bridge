#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ART = REPO / "artifacts"
PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
LOG = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt")
sys.path.insert(0, str(REPO / "tools" / "pass647_dynamic_world_port"))
from pcap_dynamic import parse_pcapng, iso_time, write_csv  # type: ignore

STATIC_KEY = b"nKO/WctQ0AVLbpzfBkS6NevDYT8ourG5CRlmdjyJ72aswx4EPq1UgZhFMXH?3iI9"


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def parse_ts(s: str):
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return dt.datetime.strptime(s.strip(), fmt).timestamp()
        except Exception:
            pass
    return None


def load_log_rows() -> tuple[list[dict], int, bool]:
    rows = []
    old_count = 0
    s2c_a_present = False
    with LOG.open("r", newline="", encoding="utf-8-sig") as f:
        for idx, row in enumerate(csv.DictReader(f), 1):
            text = (row.get("visible_text") or "").strip()
            notes = (row.get("notes") or "").lower()
            direction = (row.get("direction") or "").upper()
            if text.startswith("S2C_ORACLE_"):
                old_count += 1
            if direction == "S2C" and text.startswith("S2C_A_"):
                s2c_a_present = True
            # Pass649 forces the eight current whisper length-ladder rows from the brief.
            if direction == "S2C" and text.startswith("S2C_A_") and "whisper" in notes and not text.endswith("G"):
                rows.append({
                    "marker_index": len(rows) + 1,
                    "marker_text": text,
                    "marker_len_ascii": len(text.encode("ascii", errors="ignore")),
                    "marker_len_utf16le": len(text.encode("utf-16le", errors="ignore")),
                    "repeat_id": text,
                    "channel_guess": "whisper",
                    "logged_time": row.get("timestamp_local", ""),
                    "ts": parse_ts(row.get("timestamp_local", "")),
                    "source_row_index": idx,
                })
    return rows, old_count, s2c_a_present and old_count > 0


def nearest(pkts, ts, win):
    if ts is None:
        return None
    cand = [p for p in pkts if p.ts is not None and abs(p.ts - ts) <= win]
    return min(cand, key=lambda p: abs(p.ts - ts)) if cand else None


def nearest_any(pkts, ts):
    if not pkts:
        return None
    if ts is None:
        return pkts[0]
    cand = [p for p in pkts if p.ts is not None]
    return min(cand, key=lambda p: abs(p.ts - ts)) if cand else pkts[0]


def delta_ms(pkt, ts):
    if pkt is None or pkt.ts is None or ts is None:
        return ""
    return int(round((pkt.ts - ts) * 1000))


def correlate_markers(markers: list[dict], packets) -> list[dict]:
    rows = []
    flows = [("world_game_candidate", 7780), ("chat_sidechannel_candidate", 10242)]
    for role, port in flows:
        s2c = [p for p in packets if p.server_port_guess == port and p.direction_guess == "S2C" and p.payload_len > 0]
        c2s = [p for p in packets if p.server_port_guess == port and p.direction_guess == "C2S" and p.payload_len > 0]
        for marker in markers:
            ts = marker["ts"]
            s = c = None
            confidence = "whole_flow_fallback"
            reason = "whole-flow fallback used"
            for win, label in ((3, "exact_window_3s"), (10, "window_10s"), (30, "window_30s")):
                s = nearest(s2c, ts, win)
                c = nearest(c2s, ts, win)
                if s or c:
                    confidence = label
                    reason = f"nearest packets found within +/-{win} seconds"
                    break
            if s is None and c is None:
                s = nearest_any(s2c, ts)
                c = nearest_any(c2s, ts)
            rows.append({
                "marker_index": marker["marker_index"],
                "marker_text": marker["marker_text"],
                "marker_len_ascii": marker["marker_len_ascii"],
                "marker_len_utf16le": marker["marker_len_utf16le"],
                "repeat_id": marker["repeat_id"],
                "channel_guess": marker["channel_guess"],
                "logged_time": marker["logged_time"],
                "flow_role": role,
                "server_port": port,
                "nearest_s2c_frame": s.frame if s else "",
                "nearest_s2c_time": iso_time(s.ts) if s else "",
                "delta_ms": delta_ms(s, ts),
                "s2c_tcp_len": s.payload_len if s else "",
                "nearest_c2s_frame": c.frame if c else "",
                "nearest_c2s_time": iso_time(c.ts) if c else "",
                "c2s_delta_ms": delta_ms(c, ts),
                "c2s_tcp_len": c.payload_len if c else "",
                "confidence": confidence,
                "reason": reason,
            })
    return rows


def build_length_model(corr_rows: list[dict]) -> list[dict]:
    rows = []
    by_flow = defaultdict(list)
    for row in corr_rows:
        by_flow[(row["flow_role"], row["server_port"])].append(row)
    for (role, port), items in by_flow.items():
        items.sort(key=lambda r: int(r["marker_index"]))
        prev_len = None
        seen = defaultdict(int)
        lengths_by_marker = defaultdict(list)
        for r in items:
            if r["s2c_tcp_len"] != "":
                lengths_by_marker[r["marker_text"]].append(str(r["s2c_tcp_len"]))
        for r in items:
            text = r["marker_text"]
            seen[text] += 1
            marker_len = int(r["marker_len_ascii"])
            delta = "" if prev_len is None else marker_len - prev_len
            prev_len = marker_len
            same_lengths = lengths_by_marker[text]
            consistent = "unknown" if len(same_lengths) < 2 else str(len(set(same_lengths)) == 1).lower()
            conf = "high" if r["confidence"] == "exact_window_3s" else "medium" if r["confidence"] == "window_10s" else "low"
            rows.append({
                "flow_role": role,
                "server_port": port,
                "marker_text": text,
                "marker_len_ascii": marker_len,
                "occurrence_index": seen[text],
                "nearest_s2c_len": r["s2c_tcp_len"],
                "nearest_c2s_len": r["c2s_tcp_len"],
                "length_delta_from_previous_marker": delta,
                "same_marker_repeat_len_consistent": consistent,
                "confidence": conf,
                "reason": "length-ladder timing metadata; no payload bytes or decoded text written",
            })
    return rows


def crib_variants(text: str):
    marker = text.encode("utf-16le")
    yield "utf16le_marker", marker
    yield "utf16le_marker_nul", marker + b"\x00\x00"
    visible = "::Spirips Whispers: " + text
    yield "visible_whisper_utf16le", visible.encode("utf-16le")
    yield "visible_whisper_utf16le_nul", visible.encode("utf-16le") + b"\x00\x00"
    yield "unknown_prefix_window_utf16le", marker


def derive_slots(body: bytes, body_offset: int, crib: bytes):
    slots: dict[int, int] = {}
    conflicts = 0
    if body_offset < 0 or body_offset + len(crib) > len(body):
        return 0, 8, "none"
    for j, plain in enumerate(crib):
        pos = body_offset + j
        if pos == 0:
            val = body[0] ^ plain
        else:
            val = body[pos] ^ plain ^ STATIC_KEY[pos & 63] ^ body[pos - 1]
        slot = pos & 7
        if slot in slots and slots[slot] != val:
            conflicts += 1
        else:
            slots[slot] = val
    sig = ";".join(f"{k}:{v}" for k, v in sorted(slots.items()))
    return len(slots), conflicts, sig


def scan_candidates(corr_rows: list[dict], packets) -> list[dict]:
    world = [p for p in packets if p.server_port_guess == 7780 and p.direction_guess == "S2C" and p.payload_len > 0]
    by_frame = {p.frame: p for p in world}
    raw = []
    sigs = defaultdict(set)
    seq = 0
    rows = [r for r in corr_rows if str(r["server_port"]) == "7780"]
    counts = Counter(r["marker_text"] for r in rows)
    for row in rows:
        frames = set()
        if row["nearest_s2c_frame"]:
            frames.add(int(row["nearest_s2c_frame"]))
        anchor = by_frame.get(int(row["nearest_s2c_frame"])) if row["nearest_s2c_frame"] else None
        if anchor and anchor.ts is not None:
            for p in world:
                if p.ts is not None and abs(p.ts - anchor.ts) <= 30:
                    frames.add(p.frame)
        hits = []
        for frame in sorted(frames):
            pkt = by_frame.get(frame)
            if not pkt:
                continue
            body = pkt.payload[2:] if len(pkt.payload) > 2 else pkt.payload
            if len(body) < 8:
                continue
            for variant, crib in crib_variants(row["marker_text"]):
                if len(crib) < 8 or len(crib) > len(body):
                    continue
                for off in range(0, max(0, len(body) - len(crib) + 1), 2):
                    slots, conflicts, sig = derive_slots(body, off, crib)
                    if slots >= 8 and conflicts == 0:
                        score = min(100, 40 + len(crib) // 2 + 20)
                        hits.append((score, pkt, variant, off, slots, conflicts, sig))
        hits.sort(key=lambda x: (x[0], x[4], -x[5]), reverse=True)
        for score, pkt, variant, off, slots, conflicts, sig in hits[:40]:
            seq += 1
            sigs[row["marker_text"]].add(f"{variant}|{off}|{sig}")
            raw.append({
                "candidate_id": f"pass649_{seq:05d}",
                "marker_text": row["marker_text"],
                "frame": pkt.frame,
                "window_strategy": row["confidence"],
                "crib_variant": variant,
                "payload_len": pkt.payload_len,
                "body_offset": off,
                "slots_recovered": slots,
                "conflict_slots": conflicts,
                "all_8_covered": str(slots == 8).lower(),
                "repeat_consistency": "pending",
                "structural_score": score,
                "confidence": "medium_candidate",
                "reason": "bounded S2C_A length-ladder crib slot consistency only; derived key bytes not written",
            })
    for r in raw:
        text = r["marker_text"]
        if counts[text] < 2:
            r["repeat_consistency"] = "not_repeated_marker"
        else:
            r["repeat_consistency"] = "consistent" if len(sigs[text]) == 1 else "not_consistent"
    return raw


def write_validation(candidates: list[dict]) -> None:
    rows = []
    for c in candidates:
        structural = c["all_8_covered"] == "true" and int(c["conflict_slots"]) == 0 and int(c["structural_score"]) >= 60
        rows.append({
            "candidate_id": c["candidate_id"],
            "marker_text": c["marker_text"],
            "frame": c["frame"],
            "window_strategy": c["window_strategy"],
            "crib_variant": c["crib_variant"],
            "payload_len": c["payload_len"],
            "body_offset": c["body_offset"],
            "slots_recovered": c["slots_recovered"],
            "conflict_slots": c["conflict_slots"],
            "all_8_covered": c["all_8_covered"],
            "repeat_consistency": c["repeat_consistency"],
            "structural_score": c["structural_score"],
            "confidence": "medium_hypothesis" if structural else "low_hypothesis",
            "reason": "not independently keyrolled or exact-marker decoded; decoder success not claimed",
        })
    fields = ["candidate_id","marker_text","frame","window_strategy","crib_variant","payload_len","body_offset","slots_recovered","conflict_slots","all_8_covered","repeat_consistency","structural_score","confidence","reason"]
    write_csv(ART / "pass649_length_ladder_s2c_validation.csv", rows, fields)


def main() -> int:
    ART.mkdir(parents=True, exist_ok=True)
    markers, old_count, mixed = load_log_rows()
    packets = parse_pcapng(PCAP)
    corr = correlate_markers(markers, packets)
    corr_fields = ["marker_index","marker_text","marker_len_ascii","marker_len_utf16le","repeat_id","channel_guess","logged_time","flow_role","server_port","nearest_s2c_frame","nearest_s2c_time","delta_ms","s2c_tcp_len","nearest_c2s_frame","nearest_c2s_time","c2s_delta_ms","c2s_tcp_len","confidence","reason"]
    write_csv(ART / "pass649_length_ladder_marker_correlation_7780_10242.csv", corr, corr_fields)
    model = build_length_model(corr)
    model_fields = ["flow_role","server_port","marker_text","marker_len_ascii","occurrence_index","nearest_s2c_len","nearest_c2s_len","length_delta_from_previous_marker","same_marker_repeat_len_consistent","confidence","reason"]
    write_csv(ART / "pass649_length_ladder_model.csv", model, model_fields)
    candidates = scan_candidates(corr, packets)
    cand_fields = ["candidate_id","marker_text","frame","window_strategy","crib_variant","payload_len","body_offset","slots_recovered","conflict_slots","all_8_covered","repeat_consistency","structural_score","confidence","reason"]
    write_csv(ART / "pass649_length_ladder_s2c_candidates.csv", candidates, cand_fields)
    write_validation(candidates)
    all8 = [c for c in candidates if c["all_8_covered"] == "true"]
    rep = [c for c in candidates if c["repeat_consistency"] == "consistent"]
    decision = {
        "worker": "codex",
        "phase": "pass649_current_length_ladder_analysis",
        "current_world_port": 7780,
        "mixed_old_new_log_detected": bool(mixed),
        "old_s2c_oracle_rows_ignored": old_count,
        "length_ladder_rows_used": len(markers),
        "current_marker_set": "length_ladder",
        "reran_marker_correlation": True,
        "reran_length_model": True,
        "reran_s2c_oracle_on_length_ladder": True,
        "candidate_count": len(candidates),
        "all_8_slot_candidates": len(all8),
        "repeat_consistent_candidates": len(rep),
        "exact_marker_recovered": False,
        "s2c_keyroll_validated": False,
        "s2c_decoder_success": False,
        "needs_recapture": len(candidates) == 0 or len(rep) == 0,
        "raw_payload_committed": False,
        "raw_ciphertext_committed": False,
        "raw_plaintext_blob_committed": False,
        "packet_hashes_committed": False,
        "reason": "Forced current S2C_A_ whisper length-ladder markers and ignored old S2C_ORACLE rows; no exact marker plaintext/keyroll validation is claimed from bounded 7780 crib metadata.",
        "next_action": "If candidates remain absent or inconsistent, capture an even longer repeated ladder and add packet framing hypotheses before another keyroll attempt.",
    }
    (ART / "pass649_current_capture_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    summary = [
        "# Pass649 Current Length-Ladder Capture Analysis",
        "",
        f"Mixed old/new log detected: {decision['mixed_old_new_log_detected']}",
        f"Old S2C_ORACLE rows ignored: {old_count}",
        f"Length ladder rows used: {len(markers)}",
        f"Candidate count: {len(candidates)}",
        f"All-8-slot candidates: {len(all8)}",
        f"Repeat-consistent candidates: {len(rep)}",
        "Exact marker recovered: False",
        "S2C keyroll validated: False",
        "S2C decoder success: False",
        "",
        decision["reason"],
        "",
        "No raw payloads, ciphertext, plaintext blobs, packet hashes, keys, binaries, DLLs, EXEs, tokens, or secrets were written.",
    ]
    text = "\n".join(summary) + "\n"
    (ART / "pass649_current_capture_summary.md").write_text(text, encoding="utf-8")
    (REPO / "inbox" / "codex_report.md").write_text(text, encoding="utf-8")
    print(json.dumps(decision, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
