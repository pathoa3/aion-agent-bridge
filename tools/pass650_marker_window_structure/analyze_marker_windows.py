#!/usr/bin/env python3
from __future__ import annotations

import csv
import datetime as dt
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ART = REPO / "artifacts"
PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
LOG = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt")
sys.path.insert(0, str(REPO / "tools" / "pass647_dynamic_world_port"))
from pcap_dynamic import parse_pcapng, write_csv  # type: ignore


def parse_ts(s: str):
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return dt.datetime.strptime(s.strip(), fmt).timestamp()
        except Exception:
            pass
    return None


def load_markers() -> list[dict]:
    markers = []
    with LOG.open("r", newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            text = (row.get("visible_text") or "").strip()
            notes = (row.get("notes") or "").lower()
            direction = (row.get("direction") or "").upper()
            if direction == "S2C" and text.startswith("S2C_A_") and "whisper" in notes and not text.endswith("G"):
                markers.append({
                    "marker_index": len(markers) + 1,
                    "marker_text": text,
                    "marker_len_ascii": len(text.encode("ascii", errors="ignore")),
                    "logged_time": row.get("timestamp_local", ""),
                    "ts": parse_ts(row.get("timestamp_local", "")),
                })
    return markers


def occurrence_indexes(markers: list[dict]) -> dict[int, int]:
    counts = defaultdict(int)
    out = {}
    for m in markers:
        counts[m["marker_text"]] += 1
        out[m["marker_index"]] = counts[m["marker_text"]]
    return out


def flow_role(port: int) -> str:
    return "world_game_candidate" if port == 7780 else "chat_sidechannel_candidate"


def burst_group(delta_ms: int, direction: str) -> str:
    if delta_ms < -1000:
        side = "pre"
    elif delta_ms > 1000:
        side = "post"
    else:
        side = "near"
    return f"{side}_{direction.lower()}"


def collect_windows(markers: list[dict], packets) -> list[dict]:
    occ = occurrence_indexes(markers)
    rows = []
    for m in markers:
        if m["ts"] is None:
            continue
        for port in (7780, 10242):
            role = flow_role(port)
            flow_packets = [p for p in packets if p.server_port_guess == port and p.payload_len > 0 and p.ts is not None]
            for win in (3, 10):
                selected = [p for p in flow_packets if abs(p.ts - m["ts"]) <= win]
                selected.sort(key=lambda p: (p.ts, p.frame))
                for order, p in enumerate(selected, 1):
                    delta = int(round((p.ts - m["ts"]) * 1000))
                    rows.append({
                        "marker_index": m["marker_index"],
                        "marker_text": m["marker_text"],
                        "marker_len_ascii": m["marker_len_ascii"],
                        "occurrence_index": occ[m["marker_index"]],
                        "flow_role": role,
                        "server_port": port,
                        "window_sec": win,
                        "packet_order": order,
                        "frame": p.frame,
                        "time_delta_ms": delta,
                        "direction": p.direction_guess,
                        "tcp_len": p.payload_len,
                        "is_payload_packet": str(p.payload_len > 0).lower(),
                        "burst_group": burst_group(delta, p.direction_guess),
                        "reason": "safe packet-window metadata only",
                    })
    return rows


def normalized_lcs(a: list, b: list) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    prev = [0] * (len(b) + 1)
    for x in a:
        cur = [0]
        for j, y in enumerate(b, 1):
            cur.append(prev[j - 1] + 1 if x == y else max(prev[j], cur[-1]))
        prev = cur
    return prev[-1] / max(len(a), len(b))


def repeat_similarity(window_rows: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for r in window_rows:
        groups[(r["marker_text"], r["flow_role"], r["server_port"], r["window_sec"], r["occurrence_index"])].append(r)
    by_marker = defaultdict(list)
    for (text, role, port, win, occ), rows in groups.items():
        by_marker[(text, role, port, win)].append((occ, sorted(rows, key=lambda x: int(x["packet_order"]))))
    out = []
    for (text, role, port, win), occs in sorted(by_marker.items()):
        if len(occs) < 2:
            continue
        occs = sorted(occs, key=lambda x: int(x[0]))
        a_occ, a_rows = occs[0]
        b_occ, b_rows = occs[1]
        a_len = [int(r["tcp_len"]) for r in a_rows]
        b_len = [int(r["tcp_len"]) for r in b_rows]
        a_dir = [r["direction"] for r in a_rows]
        b_dir = [r["direction"] for r in b_rows]
        len_sim = normalized_lcs(a_len, b_len)
        dir_sim = normalized_lcs(a_dir, b_dir)
        total_a = sum(a_len)
        total_b = sum(b_len)
        conf = "high" if len_sim >= 0.75 and dir_sim >= 0.75 else "medium" if len_sim >= 0.4 or dir_sim >= 0.7 else "low"
        out.append({
            "marker_text": text,
            "flow_role": role,
            "server_port": port,
            "window_sec": win,
            "occurrence_a": a_occ,
            "occurrence_b": b_occ,
            "sequence_len_a": len(a_rows),
            "sequence_len_b": len(b_rows),
            "length_sequence_similarity": f"{len_sim:.3f}",
            "direction_sequence_similarity": f"{dir_sim:.3f}",
            "total_payload_a": total_a,
            "total_payload_b": total_b,
            "confidence": conf,
            "reason": "LCS similarity over safe length and direction sequences",
        })
    return out


def corr_hint(xs: list[int], ys: list[int]) -> str:
    pairs = [(x, y) for x, y in zip(xs, ys) if y is not None]
    if len(pairs) < 3:
        return "insufficient"
    xvals = [p[0] for p in pairs]
    yvals = [p[1] for p in pairs]
    mx = sum(xvals) / len(xvals)
    my = sum(yvals) / len(yvals)
    num = sum((x - mx) * (y - my) for x, y in pairs)
    denx = math.sqrt(sum((x - mx) ** 2 for x in xvals))
    deny = math.sqrt(sum((y - my) ** 2 for y in yvals))
    if denx == 0 or deny == 0:
        return "flat"
    r = num / (denx * deny)
    if r >= 0.6:
        return "positive"
    if r <= -0.6:
        return "negative"
    return "weak"


def monotonic(xs: list[int], ys: list[int]) -> bool:
    pairs = sorted((x, y) for x, y in zip(xs, ys) if y is not None)
    if len(pairs) < 3:
        return False
    return all(pairs[i + 1][1] >= pairs[i][1] for i in range(len(pairs) - 1))


def repeat_consistent(markers: list[dict], values: dict[tuple[int, int], int | None]) -> bool:
    by_text = defaultdict(list)
    for m in markers:
        by_text[m["marker_text"]].append(values.get((m["marker_index"], m["marker_len_ascii"])))
    comparable = []
    for vals in by_text.values():
        vals = [v for v in vals if v is not None]
        if len(vals) >= 2:
            comparable.append(len(set(vals)) == 1)
    return bool(comparable) and all(comparable)


def length_signal_model(markers: list[dict], window_rows: list[dict]) -> list[dict]:
    rows = []
    for role, port in (("world_game_candidate", 7780), ("chat_sidechannel_candidate", 10242)):
        for win in (3, 10):
            relevant = [r for r in window_rows if r["flow_role"] == role and int(r["server_port"]) == port and int(r["window_sec"]) == win]
            def value_for(marker, signal):
                rs = [r for r in relevant if int(r["marker_index"]) == marker["marker_index"]]
                if signal == "s2c_payload_plus_3s":
                    vals = [int(r["tcp_len"]) for r in rs if r["direction"] == "S2C" and 0 <= int(r["time_delta_ms"]) <= 3000]
                    return sum(vals)
                if signal == "s2c_payload_pm_window":
                    return sum(int(r["tcp_len"]) for r in rs if r["direction"] == "S2C")
                if signal == "largest_s2c_packet":
                    vals = [int(r["tcp_len"]) for r in rs if r["direction"] == "S2C"]
                    return max(vals) if vals else None
                if signal == "s2c_packet_count":
                    return sum(1 for r in rs if r["direction"] == "S2C")
                if signal == "c2s_trigger_packets_10242":
                    if port != 10242:
                        return None
                    return sum(1 for r in rs if r["direction"] == "C2S" and abs(int(r["time_delta_ms"])) <= 3000)
                return None
            for signal in ("s2c_payload_plus_3s", "s2c_payload_pm_window", "largest_s2c_packet", "s2c_packet_count", "c2s_trigger_packets_10242"):
                vals = {(m["marker_index"], m["marker_len_ascii"]): value_for(m, signal) for m in markers}
                xs = [m["marker_len_ascii"] for m in markers]
                ys = [vals[(m["marker_index"], m["marker_len_ascii"])] for m in markers]
                hint = corr_hint(xs, ys)
                mono = monotonic(xs, ys)
                rep = repeat_consistent(markers, vals)
                conf = "high" if hint == "positive" and mono and rep else "medium" if hint in ("positive", "weak") and (mono or rep) else "low"
                rows.append({
                    "flow_role": role,
                    "server_port": port,
                    "window_sec": win,
                    "signal_name": signal,
                    "rows_used": sum(1 for y in ys if y is not None),
                    "correlation_hint": hint,
                    "monotonic_with_marker_length": str(mono).lower(),
                    "repeat_consistent": str(rep).lower(),
                    "confidence": conf,
                    "reason": "safe aggregate window signal from packet length/direction metadata",
                })
    return rows


def decide(sim_rows: list[dict], signal_rows: list[dict], window_rows: list[dict]) -> dict:
    high_sim = [r for r in sim_rows if r["confidence"] == "high"]
    length_signal = [r for r in signal_rows if r["confidence"] in ("high", "medium")]
    exact_10242_triggers = [r for r in signal_rows if r["server_port"] == 10242 and r["signal_name"] == "c2s_trigger_packets_10242" and r["confidence"] in ("high", "medium")]
    if exact_10242_triggers:
        likely = "10242_sidechannel_trigger"
        next_step = "static_framing_analysis"
    elif high_sim and length_signal:
        likely = "packet_sequence"
        next_step = "packet_sequence_crib"
    elif length_signal:
        likely = "batched_event"
        next_step = "stream_reassembly"
    elif high_sim:
        likely = "packet_sequence"
        next_step = "packet_sequence_crib"
    else:
        likely = "compressed_or_encrypted"
        next_step = "manual_local_payload_inspection"
    return {
        "worker": "codex",
        "phase": "pass650_marker_window_structure",
        "current_world_port": 7780,
        "length_ladder_rows_used": 8,
        "window_packets_analyzed": len(window_rows),
        "repeat_window_similarity_found": bool(high_sim),
        "length_signal_found": bool(length_signal),
        "likely_marker_representation": likely,
        "recommended_next_step": next_step,
        "raw_payload_committed": False,
        "raw_ciphertext_committed": False,
        "raw_plaintext_blob_committed": False,
        "packet_hashes_committed": False,
        "s2c_decoder_success": False,
        "reason": "Analyzed full +/-3s and +/-10s packet length/direction windows around current S2C_A_ ladder markers; no raw payload material was written.",
        "next_action": "Use the strongest window-level signal to choose stream reassembly, packet-sequence cribbing, static framing analysis, or local-only manual payload inspection.",
    }


def main() -> int:
    ART.mkdir(parents=True, exist_ok=True)
    markers = load_markers()
    packets = parse_pcapng(PCAP)
    window_rows = collect_windows(markers, packets)
    window_fields = ["marker_index","marker_text","marker_len_ascii","occurrence_index","flow_role","server_port","window_sec","packet_order","frame","time_delta_ms","direction","tcp_len","is_payload_packet","burst_group","reason"]
    write_csv(ART / "pass650_marker_packet_windows.csv", window_rows, window_fields)
    sim_rows = repeat_similarity(window_rows)
    sim_fields = ["marker_text","flow_role","server_port","window_sec","occurrence_a","occurrence_b","sequence_len_a","sequence_len_b","length_sequence_similarity","direction_sequence_similarity","total_payload_a","total_payload_b","confidence","reason"]
    write_csv(ART / "pass650_repeat_window_similarity.csv", sim_rows, sim_fields)
    signal_rows = length_signal_model(markers, window_rows)
    signal_fields = ["flow_role","server_port","window_sec","signal_name","rows_used","correlation_hint","monotonic_with_marker_length","repeat_consistent","confidence","reason"]
    write_csv(ART / "pass650_length_signal_model.csv", signal_rows, signal_fields)
    decision = decide(sim_rows, signal_rows, window_rows)
    (ART / "pass650_window_structure_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    summary = [
        "# Pass650 Marker Window Structure",
        "",
        f"Length ladder rows used: {len(markers)}",
        f"Window packets analyzed: {len(window_rows)}",
        f"Repeat window similarity found: {decision['repeat_window_similarity_found']}",
        f"Length signal found: {decision['length_signal_found']}",
        f"Likely marker representation: {decision['likely_marker_representation']}",
        f"Recommended next step: {decision['recommended_next_step']}",
        "",
        decision["reason"],
        "",
        "No raw payloads, ciphertext, plaintext blobs, packet hashes, keys, binaries, DLLs, EXEs, tokens, or secrets were written.",
    ]
    text = "\n".join(summary) + "\n"
    (ART / "pass650_window_structure_summary.md").write_text(text, encoding="utf-8")
    (REPO / "inbox" / "codex_report.md").write_text(text, encoding="utf-8")
    print(json.dumps(decision, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
