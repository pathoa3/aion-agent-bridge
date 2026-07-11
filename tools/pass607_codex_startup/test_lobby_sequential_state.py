from __future__ import annotations

import hashlib
import json

from blowfish_pure import Blowfish
from pass607_codex_startup_common import ART, INBOX, PRIVATE, STARTUP_PCAP, public_xorpass, spaced_hex, tcp_payload_rows, write_csv

LOBBY_PACKET = 7522
LOBBY_SEED = bytes.fromhex("735a1208")
TARGET_MESSAGES = {
    8745: "KXBOOT_SAY_01",
    8844: "KXBOOT_SAY_02_AAAAAAAAAAAAAAAA",
    8974: "KXBOOT_SAY_03_1234567890",
}
TARGET_PACKETS = [8745, 8844, 8974]
KEYS = {
    "lobby_le_tail_a16c5487": bytes.fromhex("735a1208a16c5487"),
    "lobby_be_tail_a16c5487": bytes.fromhex("08125a73a16c5487"),
    "lobby_le_tail_87546ca1": bytes.fromhex("735a120887546ca1"),
    "lobby_be_tail_87546ca1": bytes.fromhex("08125a7387546ca1"),
    "lobby_le_tail_ffffffff": bytes.fromhex("735a1208ffffffff"),
    "lobby_le_tail_00000000": bytes.fromhex("735a120800000000"),
}
TRANSFORMS = [
    "Blowfish_ECB_only",
    "Blowfish_ECB_then_decXORPass",
    "decXORPass_then_Blowfish_ECB",
    "XORpass_then_Blowfish_current_key",
    "previous_best_decXORPass_then_Blowfish_ECB_xor_offset_4",
]
OFFSETS = [0, 2, 4, 6, 8]
UPDATE_RULES = [
    "A_public_update_decrypted_len",
    "B_public_update_ciphertext_len",
    "C_add_first_decrypted_dword",
    "D_add_last_decrypted_dword",
    "E_add_len_plus_first_decrypted_dword",
    "F_no_update_negative_control",
    "G_c2s_only_public_update_decrypted_len",
]


def u64_to_key(v: int) -> bytes:
    return (v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def key_to_u64(key: bytes) -> int:
    return int.from_bytes(key, "little")


def bf_decrypt_region(payload: bytes, key: bytes, offset: int) -> tuple[bytes, int, int]:
    if offset >= len(payload):
        return payload, 0, max(0, len(payload) - offset)
    block_len = ((len(payload) - offset) // 8) * 8
    leftover = len(payload) - offset - block_len
    if block_len <= 0:
        return payload, 0, leftover
    bf = Blowfish(key)
    mid = bf.decrypt_ecb(payload[offset:offset + block_len])
    return payload[:offset] + mid + payload[offset + block_len:], block_len, leftover


def apply_transform(payload: bytes, key: bytes, transform: str, offset: int) -> tuple[bytes, int, int]:
    if transform == "previous_best_decXORPass_then_Blowfish_ECB_xor_offset_4":
        x = public_xorpass(payload, key, offset=4, include_prev=True, update_size_before=False)
        return bf_decrypt_region(x, key, 0)
    if transform == "Blowfish_ECB_only":
        return bf_decrypt_region(payload, key, offset)
    if transform == "Blowfish_ECB_then_decXORPass":
        bf, block_len, leftover = bf_decrypt_region(payload, key, offset)
        return public_xorpass(bf, key, offset=offset, include_prev=True, update_size_before=False), block_len, leftover
    if transform in {"decXORPass_then_Blowfish_ECB", "XORpass_then_Blowfish_current_key"}:
        x = public_xorpass(payload, key, offset=offset, include_prev=True, update_size_before=False)
        return bf_decrypt_region(x, key, offset)
    raise ValueError(transform)


def first_dword(data: bytes) -> int:
    return int.from_bytes(data[:4], "little") if len(data) >= 4 else 0


def last_dword(data: bytes) -> int:
    return int.from_bytes(data[-4:], "little") if len(data) >= 4 else 0


def update_key(state: int, rule: str, direction: str, ciphertext: bytes, decrypted: bytes) -> int:
    if rule == "A_public_update_decrypted_len":
        return state + len(decrypted)
    if rule == "B_public_update_ciphertext_len":
        return state + len(ciphertext)
    if rule == "C_add_first_decrypted_dword":
        return state + first_dword(decrypted)
    if rule == "D_add_last_decrypted_dword":
        return state + last_dword(decrypted)
    if rule == "E_add_len_plus_first_decrypted_dword":
        return state + len(ciphertext) + first_dword(decrypted)
    if rule == "F_no_update_negative_control":
        return state
    if rule == "G_c2s_only_public_update_decrypted_len":
        return state + len(decrypted) if direction == "C2S" else state
    raise ValueError(rule)


def utf16_ratio(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    even = data[:len(data) - (len(data) % 2)]
    text = even.decode("utf-16le", errors="ignore")
    if not text:
        return 0.0
    return sum(1 for ch in text if ch.isprintable()) / len(text)


def validate(decoded: bytes, expected: str, all_messages: list[str]) -> dict[str, object]:
    matched_utf16 = [m for m in all_messages if m.encode("utf-16le") in decoded]
    matched_ascii = [m for m in all_messages if m.encode("ascii") in decoded]
    length_le = int.from_bytes(decoded[:2], "little") if len(decoded) >= 2 else -1
    length_sane = 2 <= length_le <= len(decoded) + 32
    comp_2_3 = len(decoded) > 3 and decoded[2] == ((~decoded[3]) & 0xFF)
    comp_3_4 = len(decoded) > 4 and decoded[3] == ((~decoded[4]) & 0xFF)
    comp_4_5 = len(decoded) > 5 and decoded[4] == ((~decoded[5]) & 0xFF)
    hints = []
    if length_sane:
        hints.append("length_sane")
    if comp_2_3:
        hints.append("comp_2_3")
    if comp_3_4:
        hints.append("comp_3_4")
    if comp_4_5:
        hints.append("comp_4_5")
    if decoded.count(b"\x00") >= max(2, len(decoded) // 5):
        hints.append("nul_rich")
    return {
        "exact_expected_utf16": "yes" if expected.encode("utf-16le") in decoded else "no",
        "ascii_secondary": "yes" if expected.encode("ascii") in decoded else "no",
        "matched_utf16_messages": "|".join(matched_utf16),
        "matched_ascii_messages": "|".join(matched_ascii),
        "utf16_printable_ratio": f"{utf16_ratio(decoded):.3f}",
        "length_sane": "yes" if length_sane else "no",
        "opcode_complement_any": "yes" if comp_2_3 or comp_3_4 or comp_4_5 else "no",
        "header_body_hints": "|".join(hints),
    }


def score_target(row: dict[str, object]) -> float:
    score = 0.0
    if row["exact_expected_utf16"] == "yes":
        score += 1000
    if row["ascii_secondary"] == "yes":
        score += 100
    if row["length_sane"] == "yes":
        score += 10
    if row["opcode_complement_any"] == "yes":
        score += 5
    score += float(row["utf16_printable_ratio"])
    return score


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    rows = tcp_payload_rows(STARTUP_PCAP)
    by_packet = {int(r["packet_no"]): r for r in rows}
    required = [LOBBY_PACKET, *TARGET_PACKETS]
    missing = [p for p in required if p not in by_packet]
    if missing:
        raise SystemExit(f"missing required packets: {missing}")
    flow = by_packet[LOBBY_PACKET]["flow"]
    c2s_until_last_target = [
        r for r in rows
        if r["flow"] == flow and r["direction"] == "C2S" and LOBBY_PACKET < int(r["packet_no"]) <= max(TARGET_PACKETS) and int(r["payload_len"]) > 0
    ]
    intermediate_before_8745 = [r for r in c2s_until_last_target if int(r["packet_no"]) < 8745]
    inventory_rows = []
    inv_packets = [by_packet[LOBBY_PACKET], *intermediate_before_8745, *(by_packet[p] for p in TARGET_PACKETS)]
    seen = set()
    for r in inv_packets:
        pno = int(r["packet_no"])
        if pno in seen:
            continue
        seen.add(pno)
        payload = r["payload"]
        inventory_rows.append({
            "packet_no": pno,
            "direction": r["direction"],
            "len": len(payload),
            "sha256": sha256(payload),
            "is_intermediate": "yes" if pno not in [LOBBY_PACKET, *TARGET_PACKETS] else "no",
            "is_target": "yes" if pno in TARGET_PACKETS else "no",
        })
    write_csv(ART / "pass607_codex_lobby_seq_inventory.csv", inventory_rows)

    all_messages = list(TARGET_MESSAGES.values())
    trial_rows = []
    best_target_rows = []
    for key_label, initial_key in KEYS.items():
        for transform in TRANSFORMS:
            transform_offsets = [4] if transform == "previous_best_decXORPass_then_Blowfish_ECB_xor_offset_4" else OFFSETS
            for offset in transform_offsets:
                for update_rule in UPDATE_RULES:
                    state = key_to_u64(initial_key)
                    per_target = []
                    processed_intermediate = 0
                    for pkt in c2s_until_last_target:
                        pno = int(pkt["packet_no"])
                        payload = pkt["payload"]
                        key = u64_to_key(state)
                        decoded, block_bytes, leftover = apply_transform(payload, key, transform, offset)
                        if pno in TARGET_MESSAGES:
                            val = validate(decoded, TARGET_MESSAGES[pno], all_messages)
                            target_score = score_target(val)
                            out = {
                                "candidate_key_label": key_label,
                                "initial_key_sha256": sha256(initial_key),
                                "transform": transform,
                                "offset": offset,
                                "update_rule": update_rule,
                                "packet_no": pno,
                                "direction": pkt["direction"],
                                "len": len(payload),
                                "payload_sha256": sha256(payload),
                                "block_bytes_decrypted": block_bytes,
                                "leftover_bytes": leftover,
                                "processed_intermediate_before_first_target": processed_intermediate,
                                "score": f"{target_score:.3f}",
                                **val,
                            }
                            trial_rows.append(out)
                            per_target.append(out)
                        else:
                            processed_intermediate += 1
                        state = update_key(state, update_rule, pkt["direction"], payload, decoded) & 0xFFFFFFFFFFFFFFFF
                    target_hits = sum(1 for r in per_target if r["exact_expected_utf16"] == "yes")
                    consistency = sum(float(r["score"]) for r in per_target) + (10000 if target_hits == 3 else 0)
                    if per_target:
                        best = max(per_target, key=lambda r: float(r["score"]))
                        best_target_rows.append((consistency, target_hits, best, per_target))
    write_csv(ART / "pass607_codex_lobby_seq_trials.csv", trial_rows)

    best_tuple = max(best_target_rows, key=lambda x: (x[1], x[0])) if best_target_rows else (0.0, 0, {}, [])
    best_consistency, best_hits, best, best_group = best_tuple
    matched = sorted({m for r in trial_rows for m in str(r.get("matched_utf16_messages", "")).split("|") if m})
    success = best_hits == 3 or any(r["exact_expected_utf16"] == "yes" for r in trial_rows)
    best_score = float(best.get("score", 0.0)) if best else 0.0
    decision = {
        "worker": "codex",
        "phase": "pass607_lobby_sequential_state",
        "lobby_seed": spaced_hex(LOBBY_SEED),
        "intermediate_c2s_packets_count": len(intermediate_before_8745),
        "target_packets": TARGET_PACKETS,
        "sequential_state_tested": True,
        "decoder_success": bool(success),
        "exact_plaintext_recovered": bool(success),
        "matched_messages": matched,
        "best_candidate_key": best.get("candidate_key_label", ""),
        "best_transform": f"{best.get('transform', '')} offset={best.get('offset', '')}",
        "best_update_rule": best.get("update_rule", ""),
        "best_score": best_score,
        "raw_payload_committed": False,
        "forbidden_methods_used": False,
        "reason": ("Exact KXBOOT plaintext recovered from PCAP." if success else f"Sequential key-state simulation processed {len(intermediate_before_8745)} intermediate C2S packets before packet 8745 and tested {len(trial_rows)} target decrypt rows, but no exact UTF-16LE KXBOOT plaintext was recovered."),
        "next_action": "Provide file-backed code/decompile/source evidence for the custom lobby/game-channel key update, transform, or framing variant. Do not use memory dumps, attach/debug, live process, injection, anti-cheat bypass, or packet injection.",
    }
    (ART / "pass607_codex_lobby_seq_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    summary = [
        "# Pass607 Codex Lobby Sequential Key-State Summary",
        "",
        "- raw payload committed: false",
        f"- lobby seed: `{spaced_hex(LOBBY_SEED)}`",
        f"- intermediate C2S packets after 7522 and before 8745: {len(intermediate_before_8745)}",
        f"- target packets: {', '.join(str(p) for p in TARGET_PACKETS)}",
        f"- sequential state tested: yes",
        f"- candidate initial keys: {len(KEYS)}",
        f"- transforms: {len(TRANSFORMS)}",
        f"- update rules: {len(UPDATE_RULES)}",
        f"- target decrypt rows: {len(trial_rows)}",
        f"- exact UTF-16LE KXBOOT matches: {sum(1 for r in trial_rows if r['exact_expected_utf16'] == 'yes')}",
        f"- matched messages: {', '.join(matched) if matched else '(none)'}",
        f"- best candidate key: {decision['best_candidate_key']}",
        f"- best transform: {decision['best_transform']}",
        f"- best update rule: {decision['best_update_rule']}",
        f"- best score: {decision['best_score']:.3f}",
        "- no raw packet hex, decoded bytes, ciphertext blobs, or decrypted prefixes are included in these artifacts.",
    ]
    (ART / "pass607_codex_lobby_seq_summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    report = [
        "# Codex Pass607 Lobby Sequential State Report",
        "",
        f"Decision: `{'decoder_success' if success else 'blocked_lobby_seq_no_plaintext_recovery'}`",
        "",
        f"- 31 intermediate C2S packets processed: {'yes' if len(intermediate_before_8745) == 31 else 'no'} ({len(intermediate_before_8745)})",
        "- sequential key-state simulation tested: yes",
        f"- exact KXBOOT plaintext recovered: {'yes' if success else 'no'}",
        f"- matched messages: {', '.join(matched) if matched else '(none)'}",
        f"- best update rule: {decision['best_update_rule']}",
        f"- best transform: {decision['best_transform']}",
        f"- best candidate key: {decision['best_candidate_key']}",
        f"- best score: {decision['best_score']:.3f}",
        "- raw payload committed: false",
        "",
        "No forbidden methods were used. Next action is file-backed code/decompile/source evidence for the custom lobby/game-channel key update, transform, or framing variant. Memory dumps are not recommended.",
    ]
    INBOX.mkdir(parents=True, exist_ok=True)
    (INBOX / "codex_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(json.dumps(decision, indent=2))
    if success:
        out = PRIVATE / "outbox"
        out.mkdir(parents=True, exist_ok=True)
        (out / "decoded_cleartext.txt").write_text("\n".join(matched) + "\n", encoding="utf-8")
        (out / "decoder_success.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
