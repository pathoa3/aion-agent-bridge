from __future__ import annotations

import csv
import json
from pathlib import Path

from blowfish_pure import Blowfish
from pass607_codex_startup_common import ART, INBOX, PRIVATE, STARTUP_PCAP, public_xorpass, spaced_hex, tcp_payload_rows

LOBBY_PACKET = 7522
LOBBY_SEED = bytes.fromhex("735a1208")
TARGET_MESSAGES = {
    8745: "KXBOOT_SAY_01",
    8844: "KXBOOT_SAY_02_AAAAAAAAAAAAAAAA",
    8974: "KXBOOT_SAY_03_1234567890",
}
TARGET_PACKETS = [8745, 8844, 8974]
START_KEYS = {
    "lobby_le_tail_a16c5487": bytes.fromhex("735a1208a16c5487"),
    "lobby_be_tail_a16c5487": bytes.fromhex("08125a73a16c5487"),
    "lobby_le_tail_87546ca1": bytes.fromhex("735a120887546ca1"),
    "lobby_be_tail_87546ca1": bytes.fromhex("08125a7387546ca1"),
    "formula_a9ea2bc5_tail_00000000": bytes.fromhex("a9ea2bc500000000"),
    "lobby_le_tail_00000000": bytes.fromhex("735a120800000000"),
    "lobby_le_tail_ffffffff_previous_best": bytes.fromhex("735a1208ffffffff"),
}
TRANSFORMS = [
    "Blowfish_then_decXORPass",
    "decXORPass_then_Blowfish",
    "Blowfish_only",
    "XORpass_only",
]
OFFSETS = [0, 2, 4, 6, 8]
UPDATE_RULES = ["A", "B", "C", "D", "E", "F", "G", "H"]
LOCAL_OUT = PRIVATE / "outbox" / "pass607_seq_local"


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0].keys()) if rows else ["status"]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def key_to_u64(key: bytes) -> int:
    return int.from_bytes(key, "little")


def u64_to_key(value: int) -> bytes:
    return (value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def dword_first(data: bytes) -> int:
    return int.from_bytes(data[:4], "little") if len(data) >= 4 else 0


def dword_last(data: bytes) -> int:
    return int.from_bytes(data[-4:], "little") if len(data) >= 4 else 0


def bf_region(payload: bytes, key: bytes, offset: int) -> tuple[bytes, int, int]:
    if offset >= len(payload):
        return payload, 0, max(0, len(payload) - offset)
    block_len = ((len(payload) - offset) // 8) * 8
    leftover = len(payload) - offset - block_len
    if block_len <= 0:
        return payload, 0, leftover
    mid = Blowfish(key).decrypt_ecb(payload[offset:offset + block_len])
    return payload[:offset] + mid + payload[offset + block_len:], block_len, leftover


def transform(payload: bytes, key: bytes, name: str, offset: int) -> tuple[bytes, int, int]:
    if name == "Blowfish_only":
        return bf_region(payload, key, offset)
    if name == "XORpass_only":
        return public_xorpass(payload, key, offset=offset, include_prev=True, update_size_before=False), 0, len(payload)
    if name == "Blowfish_then_decXORPass":
        bf, blocks, leftover = bf_region(payload, key, offset)
        return public_xorpass(bf, key, offset=offset, include_prev=True, update_size_before=False), blocks, leftover
    if name == "decXORPass_then_Blowfish":
        x = public_xorpass(payload, key, offset=offset, include_prev=True, update_size_before=False)
        return bf_region(x, key, offset)
    raise ValueError(name)


def update_state(state: int, rule: str, c2s_counter: int, ciphertext: bytes, decoded: bytes) -> int:
    if rule == "A":
        return state + dword_first(decoded)
    if rule == "B":
        return state + dword_last(decoded)
    if rule == "C":
        return state + dword_first(ciphertext)
    if rule == "D":
        return state + dword_last(ciphertext)
    if rule == "E":
        return state + len(ciphertext) + dword_first(decoded)
    if rule == "F":
        return state + c2s_counter
    if rule == "G":
        return state
    if rule == "H":
        # Full-stream variant: update on every data packet using length plus first decoded DWORD.
        return state + len(ciphertext) + dword_first(decoded)
    raise ValueError(rule)


def utf16_ratio(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    even = data[:len(data) - (len(data) % 2)]
    text = even.decode("utf-16le", errors="ignore")
    if not text:
        return 0.0
    return sum(1 for ch in text if ch.isprintable()) / len(text)


def validate(decoded: bytes, expected: str, labels: list[str]) -> dict[str, object]:
    matched_utf16 = [m for m in labels if m.encode("utf-16le") in decoded]
    matched_ascii = [m for m in labels if m.encode("ascii") in decoded]
    length_le = int.from_bytes(decoded[:2], "little") if len(decoded) >= 2 else -1
    length_sane = 2 <= length_le <= len(decoded) + 32
    complement = False
    for a, b in ((2, 3), (3, 4), (4, 5)):
        if len(decoded) > b and decoded[a] == ((~decoded[b]) & 0xFF):
            complement = True
    return {
        "exact_utf16": expected.encode("utf-16le") in decoded,
        "ascii_secondary": expected.encode("ascii") in decoded,
        "matched_utf16": matched_utf16,
        "matched_ascii": matched_ascii,
        "utf16_ratio": utf16_ratio(decoded),
        "length_sane": length_sane,
        "opcode_complement": complement,
    }


def score(v: dict[str, object]) -> float:
    return (
        (1000 if v["exact_utf16"] else 0)
        + (100 if v["ascii_secondary"] else 0)
        + (10 if v["length_sane"] else 0)
        + (5 if v["opcode_complement"] else 0)
        + float(v["utf16_ratio"])
    )


def local_row(candidate: str, update_rule: str, transform_name: str, offset: int, packet_no: int, v: dict[str, object], row_score: float, c2s_seen: int) -> dict[str, object]:
    return {
        "candidate_label": candidate,
        "update_rule": update_rule,
        "transform": transform_name,
        "offset": offset,
        "packet_no": packet_no,
        "c2s_data_packets_seen_before_decrypt": c2s_seen,
        "exact_utf16": "yes" if v["exact_utf16"] else "no",
        "ascii_secondary": "yes" if v["ascii_secondary"] else "no",
        "matched_utf16_labels": "|".join(v["matched_utf16"]),
        "matched_ascii_labels": "|".join(v["matched_ascii"]),
        "utf16_printable_ratio": f"{float(v['utf16_ratio']):.3f}",
        "length_sane": "yes" if v["length_sane"] else "no",
        "opcode_complement": "yes" if v["opcode_complement"] else "no",
        "score": f"{row_score:.3f}",
    }


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    LOCAL_OUT.mkdir(parents=True, exist_ok=True)
    rows = tcp_payload_rows(STARTUP_PCAP)
    by_packet = {int(r["packet_no"]): r for r in rows}
    missing = [p for p in [LOBBY_PACKET, *TARGET_PACKETS] if p not in by_packet]
    if missing:
        raise SystemExit(f"missing required packets: {missing}")
    flow = by_packet[LOBBY_PACKET]["flow"]
    c2s_stream = [
        r for r in rows
        if r["flow"] == flow and r["direction"] == "C2S" and LOBBY_PACKET < int(r["packet_no"]) <= max(TARGET_PACKETS) and int(r["payload_len"]) > 0
    ]
    full_stream = [
        r for r in rows
        if r["flow"] == flow and LOBBY_PACKET < int(r["packet_no"]) <= max(TARGET_PACKETS) and int(r["payload_len"]) > 0
    ]
    strict_intermediates = [r for r in c2s_stream if int(r["packet_no"]) < min(TARGET_PACKETS)]
    labels = list(TARGET_MESSAGES.values())
    local_rows: list[dict[str, object]] = []
    best = {"score": -1.0}
    matched: set[str] = set()
    exact_any = False

    for candidate_label, start_key in START_KEYS.items():
        for transform_name in TRANSFORMS:
            for offset in OFFSETS:
                for rule in UPDATE_RULES:
                    state = key_to_u64(start_key)
                    stream = full_stream if rule == "H" else c2s_stream
                    c2s_counter = 0
                    per_combo_scores = []
                    per_combo_exact = 0
                    for pkt in stream:
                        packet_no = int(pkt["packet_no"])
                        direction = pkt["direction"]
                        payload = pkt["payload"]
                        if direction == "C2S":
                            c2s_counter += 1
                        key = u64_to_key(state)
                        decoded, _blocks, _leftover = transform(payload, key, transform_name, offset)
                        if packet_no in TARGET_MESSAGES:
                            v = validate(decoded, TARGET_MESSAGES[packet_no], labels)
                            row_score = score(v)
                            local_rows.append(local_row(candidate_label, rule, transform_name, offset, packet_no, v, row_score, c2s_counter - 1))
                            per_combo_scores.append(row_score)
                            if v["exact_utf16"]:
                                exact_any = True
                                per_combo_exact += 1
                            matched.update(v["matched_utf16"])
                            combo_score = sum(per_combo_scores) + (10000 if per_combo_exact == len(TARGET_PACKETS) else 0)
                            if combo_score > float(best.get("score", -1.0)):
                                best = {
                                    "score": combo_score,
                                    "candidate": candidate_label,
                                    "update_rule": rule,
                                    "transform": transform_name,
                                    "offset": offset,
                                    "per_combo_exact": per_combo_exact,
                                }
                        state = update_state(state, rule, c2s_counter, payload, decoded) & 0xFFFFFFFFFFFFFFFF

    write_csv(LOCAL_OUT / "seq_trials_full.csv", local_rows)
    notes = [
        "# Pass607 Sequential State Local Debug Notes",
        "",
        "Detailed results are local-only and intentionally not committed.",
        f"- strict C2S data intermediates before packet 8745: {len(strict_intermediates)}",
        f"- C2S data packets through first target 8745: {len([r for r in c2s_stream if int(r['packet_no']) <= 8745])}",
        f"- target packets tested: {TARGET_PACKETS}",
        f"- local trial rows: {len(local_rows)}",
        f"- exact UTF-16LE matches: {sum(1 for r in local_rows if r['exact_utf16'] == 'yes')}",
        f"- best candidate label: {best.get('candidate', '')}",
        f"- best update rule: {best.get('update_rule', '')}",
        f"- best transform: {best.get('transform', '')} offset={best.get('offset', '')}",
        f"- best score: {float(best.get('score', 0.0)):.3f}",
        "- no raw packet payload hex or decoded byte blobs are written here.",
    ]
    (LOCAL_OUT / "seq_debug_notes.md").write_text("\n".join(notes) + "\n", encoding="utf-8")

    decision = {
        "worker": "codex",
        "phase": "pass607_lobby_sequential_state",
        "lobby_seed": spaced_hex(LOBBY_SEED),
        "intermediate_c2s_packets_count": len([r for r in c2s_stream if int(r["packet_no"]) <= 8745]),
        "target_packets_tested": TARGET_PACKETS,
        "sequential_state_tested": True,
        "update_rules_tested": UPDATE_RULES,
        "offsets_tested": OFFSETS,
        "trial_rows_local_only": len(local_rows),
        "decoder_success": bool(exact_any),
        "exact_plaintext_recovered": bool(exact_any),
        "matched_messages_count": len(matched),
        "matched_messages_labels": sorted(matched),
        "best_candidate_label": best.get("candidate", ""),
        "best_update_rule": best.get("update_rule", ""),
        "best_transform": f"{best.get('transform', '')} offset={best.get('offset', '')}",
        "best_score": round(float(best.get("score", 0.0)), 3),
        "raw_payload_committed": False,
        "payload_hash_committed": False,
        "forbidden_methods_used": False,
        "reason": ("Exact KXBOOT plaintext recovered from PCAP." if exact_any else f"Sequential key-state simulation tested {len(local_rows)} local-only rows across the 31 C2S data packets through first target 8745, but no exact UTF-16LE KXBOOT plaintext was recovered."),
        "next_action": "Provide file-backed code/decompile/source evidence for the custom lobby/game-channel key update, transform, or framing variant. Do not use memory dumps, attach/debug, live process, injection, anti-cheat bypass, or packet injection.",
    }
    (ART / "pass607_codex_lobby_seq_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    summary = [
        "# Pass607 Codex Lobby Sequential Key-State Summary",
        "",
        "- Git-safe summary only; detailed trial rows are local-only.",
        "- raw payload committed: false",
        "- payload hash committed: false",
        f"- lobby seed: `{spaced_hex(LOBBY_SEED)}`",
        f"- strict C2S data intermediates before 8745: {len(strict_intermediates)}",
        f"- C2S data packets through first target 8745: {decision['intermediate_c2s_packets_count']}",
        f"- target packets tested: {', '.join(str(p) for p in TARGET_PACKETS)}",
        "- sequential state tested: yes",
        f"- update rules tested: {', '.join(UPDATE_RULES)}",
        f"- offsets tested: {', '.join(str(o) for o in OFFSETS)}",
        f"- local-only trial rows: {len(local_rows)}",
        f"- exact UTF-16LE KXBOOT matches: {sum(1 for r in local_rows if r['exact_utf16'] == 'yes')}",
        f"- matched message labels: {', '.join(sorted(matched)) if matched else '(none)'}",
        f"- best candidate label: {decision['best_candidate_label']}",
        f"- best update rule: {decision['best_update_rule']}",
        f"- best transform: {decision['best_transform']}",
        f"- best score: {decision['best_score']:.3f}",
    ]
    (ART / "pass607_codex_lobby_seq_summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    report = [
        "# Codex Pass607 Lobby Sequential State Report",
        "",
        f"Decision: `{'decoder_success' if exact_any else 'blocked_lobby_seq_no_plaintext_recovery'}`",
        "",
        f"- 31 intermediate C2S packets processed: yes ({decision['intermediate_c2s_packets_count']} C2S data packets through first target 8745)",
        "- sequential key-state simulation tested: yes",
        f"- exact KXBOOT plaintext recovered: {'yes' if exact_any else 'no'}",
        f"- matched messages: {', '.join(sorted(matched)) if matched else '(none)'}",
        f"- best update rule: {decision['best_update_rule']}",
        f"- best transform: {decision['best_transform']}",
        f"- best candidate label: {decision['best_candidate_label']}",
        f"- best score: {decision['best_score']:.3f}",
        "- detailed results stayed local-only: yes",
        "- raw payload/hash data excluded from Git outputs: yes",
        "",
        "No forbidden methods were used. Next action is file-backed code/decompile/source evidence for the custom lobby/game-channel key update, transform, or framing variant. Memory dumps are not recommended.",
    ]
    INBOX.mkdir(parents=True, exist_ok=True)
    (INBOX / "codex_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(json.dumps(decision, indent=2))
    if exact_any:
        out = PRIVATE / "outbox"
        out.mkdir(parents=True, exist_ok=True)
        (out / "decoded_cleartext.txt").write_text("\n".join(sorted(matched)) + "\n", encoding="utf-8")
        (out / "decoder_success.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
