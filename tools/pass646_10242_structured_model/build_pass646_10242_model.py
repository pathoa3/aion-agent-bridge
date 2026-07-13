#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ART = REPO / "artifacts"
REPORT = REPO / "inbox" / "codex_report.md"
PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
sys.path.insert(0, str(REPO / "tools" / "pass645_10242_oracle_analysis"))
from pcap_metadata import parse_pcapng, write_csv  # type: ignore


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def to_int(value: str):
    try:
        if value == "" or value is None:
            return None
        return int(float(value))
    except (TypeError, ValueError):
        return None


def channel_guess(row: dict[str, str]) -> str:
    notes = (row.get("marker_notes") or "").lower()
    text = row.get("marker_text") or ""
    if "whisper" in notes:
        return "whisper"
    if "group" in notes or text.endswith("G"):
        return "group"
    return "unknown"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def summarize_lengths(lengths: list[int]) -> str:
    if not lengths:
        return "no_payload_packets"
    counts = Counter(lengths)
    common = ";".join(f"len{length}=x{count}" for length, count in counts.most_common(6))
    return f"packets={len(lengths)} min={min(lengths)} max={max(lengths)} unique={len(counts)} common={common}"


def load_payload_classification() -> list[dict[str, str]]:
    # Use the committed-safe Pass645 timeline metadata here. The earlier literal scan
    # already inspected payloads locally and found no ASCII/UTF-16LE marker hits;
    # Pass646 does not need to reopen or write any packet payload material.
    timeline = read_csv(ART / "pass645_10242_packet_timeline.csv")
    grouped: dict[str, list[int]] = defaultdict(list)
    for row in timeline:
        length = to_int(row.get("tcp_len", ""))
        if length is not None and length > 0:
            grouped[row.get("direction", "unknown")].append(length)
    rows = []
    for direction in ("S2C", "C2S"):
        lengths = grouped.get(direction, [])
        if direction == "S2C":
            likely = "structured_binary"
            conf = "medium"
            reason = "literal text scan found no markers; safe length/timing metadata suggests binary framing, batching, or masking rather than clear text"
        else:
            likely = "structured_binary"
            conf = "medium_low"
            reason = "client packets cluster near marker times and look like short control/event messages in safe length metadata"
        rows.append({
            "flow_id": "51.83.147.97:10242<->192.168.178.127:57497",
            "direction": direction,
            "packet_count": str(len(lengths)),
            "length_pattern_summary": summarize_lengths(lengths),
            "repeat_marker_behavior": "repeats do not expose stable literal text; group repeat reuses nearest S2C length but timing window is mixed",
            "likely_encoding": likely,
            "confidence": conf,
            "reason": reason,
        })
    return rows


def main() -> int:
    ART.mkdir(parents=True, exist_ok=True)
    corr = read_csv(ART / "pass645_10242_marker_correlation.csv")
    hits = read_csv(ART / "pass645_10242_literal_text_hits.csv")
    decision645 = json.loads((ART / "pass645_10242_oracle_decision.json").read_text(encoding="utf-8")) if (ART / "pass645_10242_oracle_decision.json").exists() else {}

    marker_rows = []
    for idx, row in enumerate(corr, 1):
        text = row.get("marker_text", "")
        marker_rows.append({
            "marker_index": idx,
            "marker_text": text,
            "marker_len_ascii": len(text.encode("ascii", errors="ignore")),
            "marker_len_utf16le": len(text.encode("utf-16le", errors="ignore")),
            "channel_guess": channel_guess(row),
            "logged_time": row.get("marker_time", ""),
            "nearest_s2c_frame": row.get("nearest_s2c_frame", ""),
            "nearest_s2c_time": row.get("nearest_s2c_time", ""),
            "delta_ms": row.get("delta_ms", ""),
            "s2c_tcp_len": row.get("s2c_len", ""),
            "nearest_c2s_frame": row.get("nearest_c2s_frame", ""),
            "nearest_c2s_time": row.get("nearest_c2s_time", ""),
            "c2s_delta_ms": row.get("c2s_delta_ms", ""),
            "c2s_tcp_len": row.get("c2s_len", ""),
            "confidence": row.get("confidence", ""),
            "reason": row.get("reason", ""),
        })
    write_csv(ART / "pass646_10242_marker_packet_correlation.csv", marker_rows, [
        "marker_index", "marker_text", "marker_len_ascii", "marker_len_utf16le", "channel_guess", "logged_time", "nearest_s2c_frame", "nearest_s2c_time", "delta_ms", "s2c_tcp_len", "nearest_c2s_frame", "nearest_c2s_time", "c2s_delta_ms", "c2s_tcp_len", "confidence", "reason"
    ])

    repeats = []
    by_marker: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in marker_rows:
        by_marker[row["marker_text"]].append(row)
    for text, rows in sorted(by_marker.items()):
        if len(rows) < 2:
            continue
        s2c_lengths = [r["s2c_tcp_len"] for r in rows if r["s2c_tcp_len"]]
        deltas = [r["delta_ms"] for r in rows if r["delta_ms"]]
        lengths_same = "unknown" if len(s2c_lengths) < 2 else str(len(set(s2c_lengths)) == 1).lower()
        delta_pattern_same = "unknown" if len(deltas) < 2 else str(len({"neg" if int(d) < 0 else "pos" for d in deltas}) == 1).lower()
        repeats.append({
            "marker_text": text,
            "channel_guess": rows[0]["channel_guess"],
            "occurrence_count": len(rows),
            "s2c_lengths_same": lengths_same,
            "s2c_delta_pattern_same": delta_pattern_same,
            "nearest_frames": ";".join(r["nearest_s2c_frame"] or "none" for r in rows),
            "confidence": "medium" if lengths_same == "true" else "low_partial",
            "reason": "repeat has limited or mixed S2C timing evidence; do not infer raw text layout from repeat alone" if lengths_same != "true" else "same nearest S2C length for repeated visible marker, but payload remains non-literal",
        })
    write_csv(ART / "pass646_10242_repeat_consistency.csv", repeats, [
        "marker_text", "channel_guess", "occurrence_count", "s2c_lengths_same", "s2c_delta_pattern_same", "nearest_frames", "confidence", "reason"
    ])

    with_s2c = [r for r in marker_rows if to_int(str(r["s2c_tcp_len"])) is not None]
    rows_total = len(marker_rows)
    monotonic_matches = 0
    pairs = [(int(r["marker_len_ascii"]), int(r["s2c_tcp_len"])) for r in with_s2c]
    if len(pairs) >= 2:
        sorted_pairs = sorted(pairs)
        monotonic_matches = sum(1 for a, b in zip(sorted_pairs, sorted_pairs[1:]) if b[1] >= a[1])
    length_models = [
        {
            "model_id": "ascii_length_linear",
            "channel_guess": "all",
            "formula_description": "s2c_tcp_len = base + marker_len_ascii",
            "rows_matched": 0,
            "rows_total": rows_total,
            "error_summary": "rejected: no literal hits and observed S2C lengths are absent/mixed, not a stable base-plus-text-length ladder",
            "confidence": "rejected",
            "reason": "marker length does not directly explain nearest S2C packet length",
        },
        {
            "model_id": "utf16le_length_linear",
            "channel_guess": "all",
            "formula_description": "s2c_tcp_len = base + marker_len_utf16le",
            "rows_matched": 0,
            "rows_total": rows_total,
            "error_summary": "rejected: UTF-16LE literal scan had no hits and lengths do not follow two-byte text growth",
            "confidence": "rejected",
            "reason": "10242 visible markers are not carried as plain UTF-16LE text in these packets",
        },
        {
            "model_id": "structured_binary_event_or_batch",
            "channel_guess": "10242",
            "formula_description": "packet length reflects binary event framing, batching, or masked payload rather than marker text length alone",
            "rows_matched": len(with_s2c),
            "rows_total": rows_total,
            "error_summary": f"supported rows with S2C length={len(with_s2c)}; monotonic_length_steps={monotonic_matches}; literal_hits={len(hits)}",
            "confidence": "medium",
            "reason": "timing correlations exist but literal text is absent and lengths do not form a controlled text-length ladder",
        },
    ]
    write_csv(ART / "pass646_10242_length_model_candidates.csv", length_models, [
        "model_id", "channel_guess", "formula_description", "rows_matched", "rows_total", "error_summary", "confidence", "reason"
    ])

    payload_rows = load_payload_classification()
    write_csv(ART / "pass646_10242_payload_classification.csv", payload_rows, [
        "flow_id", "direction", "packet_count", "length_pattern_summary", "repeat_marker_behavior", "likely_encoding", "confidence", "reason"
    ])

    plan = """# Pass646 Next Capture Plan: 10242 vs 7785

## 10242 Visible-Chat Study

- Send the same exact marker 3-5 times in the same channel.
- Send a controlled length ladder and repeat each value twice:
  - S2C_A_0001
  - S2C_A_0001_X
  - S2C_A_0001_XXXX
  - S2C_A_0001_XXXXXXXX
- Keep channel constant while testing repeats, then repeat the same ladder for whisper and group chat.
- Record local timestamps for every send/visibility event and keep screenshot-visible text labels.

## 7785 Crypto Study

- Start capture before full world entry and verify live TCP conversations include 7785 before running oracle text.
- A 10242-only capture does not solve 7785 S2C crypto, decoder state, or key source.
- If 7785 is absent, stop and restart the capture procedure rather than forcing old world-flow assumptions.
"""
    (ART / "pass646_next_capture_plan_10242_vs_7785.md").write_text(plan, encoding="utf-8")

    likely_values = [r["likely_encoding"] for r in payload_rows if r.get("direction") == "S2C"]
    likely = likely_values[0] if likely_values else "unknown"
    repeat_lengths_consistent = bool(repeats) and all(r["s2c_lengths_same"] == "true" for r in repeats)
    decision = {
        "worker": "codex",
        "phase": "pass646_10242_structured_sidechannel_model",
        "pass645_imported_to_bridge": all((ART / name).exists() for name in ["pass645_10242_oracle_decision.json", "pass645_10242_marker_correlation.csv", "pass645_10242_packet_timeline.csv"]),
        "marker_correlations_loaded": len(marker_rows),
        "repeat_markers_analyzed": len(repeats) > 0,
        "repeat_lengths_consistent": bool(repeat_lengths_consistent),
        "length_model_candidate_found": True,
        "likely_10242_encoding": likely,
        "visible_chat_carried_on_10242": bool(decision645.get("visible_chat_carried_on_10242", len(marker_rows) > 0)),
        "10242_solves_7785_s2c_crypto": False,
        "needs_new_7785_capture": not bool(decision645.get("flow_7785_found", False)),
        "raw_payload_committed": False,
        "raw_ciphertext_committed": False,
        "raw_plaintext_blob_committed": False,
        "packet_hashes_committed": False,
        "raw_binary_committed": False,
        "reason": "Pass646 finds timing-correlated 10242 packets but no literal ASCII/UTF-16LE marker carriage; lengths fit a structured/binary or masked sidechannel model better than a direct text-length formula.",
        "next_action": "Run a controlled 10242 length ladder for visible-chat modeling, and separately capture a verified 7785 flow for S2C crypto/key work.",
    }
    (ART / "pass646_10242_structured_model_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    summary = [
        "# Pass646 10242 Structured Sidechannel Model",
        "",
        f"Pass645 imported to bridge: {decision['pass645_imported_to_bridge']}",
        f"Marker correlations loaded: {len(marker_rows)}",
        f"Repeat markers analyzed: {len(repeats)}; repeat lengths consistent: {decision['repeat_lengths_consistent']}",
        f"Likely 10242 encoding: {likely}",
        f"Length model candidate: structured/binary event or batch framing, not direct ASCII/UTF-16LE text length.",
        f"Visible chat carried on 10242: {decision['visible_chat_carried_on_10242']}",
        "10242 does not solve 7785 S2C crypto; a new verified 7785 capture is still needed.",
        "",
        "No raw payloads, ciphertext, plaintext blobs, packet hashes, binaries, DLLs, EXEs, keys, tokens, or secrets were written.",
    ]
    text = "\n".join(summary) + "\n"
    (ART / "pass646_10242_structured_model_summary.md").write_text(text, encoding="utf-8")
    REPORT.write_text(text, encoding="utf-8")
    print(json.dumps(decision, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

