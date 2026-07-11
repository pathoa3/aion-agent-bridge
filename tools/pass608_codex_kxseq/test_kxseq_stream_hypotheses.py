from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

BRIDGE = Path(r"C:\AionTools\aion-agent-bridge")
PRIVATE = Path(r"C:\AionTools\aion_decoder_agent")
PASS607_TOOLS = BRIDGE / "tools" / "pass607_codex_startup"
sys.path.insert(0, str(PASS607_TOOLS))

from pass607_codex_startup_common import spaced_hex, tcp_payload_rows, public_xorpass  # noqa: E402
try:  # noqa: E402
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    from cryptography.hazmat.decrepit.ciphers import algorithms
    BLOWFISH_PROVIDER = "cryptography"
except Exception:  # noqa: E402
    Cipher = None
    modes = None
    algorithms = None
    from blowfish_pure import Blowfish
    BLOWFISH_PROVIDER = "pure_python"

CAPTURE = PRIVATE / "inbox" / "captures" / "startup_world_open_kxseq.pcapng"
LOCAL_OUT = PRIVATE / "outbox" / "pass608_kxseq_local"
ART = BRIDGE / "artifacts"
INBOX = BRIDGE / "inbox"
PREV_LOCAL = LOCAL_OUT / "kxseq_world_seed_seq_trials_full.csv"

WORLD_SEED = bytes.fromhex("2d66bd65")
LOBBY_SEED = bytes.fromhex("191a7623")
WORLD_SMKEY_FRAME = 4119
FIRST_MESSAGE_FRAME = 4329
TARGETS = [
    (4329, "KXSEQ_001"),
    (4353, "KXSEQ_002_A"),
    (4360, "KXSEQ_003_AA"),
    (4389, "KXSEQ_004_AAA"),
    (4399, "KXSEQ_005_AAAA"),
    (4402, "KXSEQ_006_AAAAAAAA"),
    (4412, "KXSEQ_007_AAAAAAAAAAAAAAAA"),
    (4417, "KXSEQ_008_0123456789"),
    (4422, "KXSEQ_009_ABABABABABABABAB"),
    (4429, "KXSEQ_010_REPEAT"),
    (4435, "KXSEQ_010_REPEAT"),
]
TARGET_BY_PACKET = dict(TARGETS)
TARGET_MESSAGES = [m for _p, m in TARGETS]
REPEAT_FRAMES = (4429, 4435)
PERIODS = [1, 2, 4, 7, 8, 10, 16, 32]
BODY_OFFSETS = [0, 2, 4, 6, 8, 10]
BODY_ONLY_OFFSETS = [4, 6, 8, 10]
START_KEYS = {
    "world_seed_tail_87546ca1_priority": bytes.fromhex("2d66bd6587546ca1"),
    "world_seed_tail_a16c5487": bytes.fromhex("2d66bd65a16c5487"),
    "world_seed_rev_tail_87546ca1": bytes.fromhex("65bd662d87546ca1"),
    "world_seed_rev_tail_a16c5487": bytes.fromhex("65bd662da16c5487"),
    "world_seed_tail_00000000": bytes.fromhex("2d66bd6500000000"),
    "world_seed_tail_ffffffff": bytes.fromhex("2d66bd65ffffffff"),
    "negative_lobby_tail_a16c5487": bytes.fromhex("191a7623a16c5487"),
    "negative_lobby_rev_tail_a16c5487": bytes.fromhex("23761a19a16c5487"),
}
STREAM_MODELS = [
    "A_Blowfish_CFB_like",
    "B_Blowfish_OFB_like",
    "C_Blowfish_CTR_frame_counter",
    "D_Blowfish_CTR_c2s_counter",
    "E_Blowfish_CTR_running_byte_counter",
    "F_XORpass_LCG_seed_stream",
    "G_XORpass_plus_packet_counter",
    "H_RC4_like_session_stream",
    "M_header_separate_body_transform",
]
STATE_MODES = ["direct_per_packet", "sequential_c2s_15", "bidirectional_state", "no_update_control"]


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = list(rows[0].keys()) if rows else ["status"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def bf_encrypt_block(key: bytes, block: bytes) -> bytes:
    if BLOWFISH_PROVIDER == "cryptography":
        encryptor = Cipher(algorithms.Blowfish(key), modes.ECB()).encryptor()
        return encryptor.update(block) + encryptor.finalize()
    return Blowfish(key).encrypt_ecb(block)


def xor_bytes(data: bytes, stream: bytes) -> bytes:
    return bytes(b ^ stream[i] for i, b in enumerate(data))


def block_from_counter(value: int, salt: int = 0) -> bytes:
    return (((value & 0xFFFFFFFF) | ((salt & 0xFFFFFFFF) << 32)) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def mutate_key(key: bytes, delta: int) -> bytes:
    return ((int.from_bytes(key, "little") + delta) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def cfb_like(key: bytes, data: bytes, counter: int, salt: int) -> bytes:
    out = bytearray()
    feedback = block_from_counter(counter, salt)
    for off in range(0, len(data), 8):
        ks = bf_encrypt_block(key, feedback)
        chunk = data[off:off + 8]
        plain = xor_bytes(chunk, ks[:len(chunk)])
        out.extend(plain)
        feedback = (chunk + ks)[:8]
    return bytes(out)


def ofb_like(key: bytes, data: bytes, counter: int, salt: int) -> bytes:
    out = bytearray()
    feedback = block_from_counter(counter, salt)
    for off in range(0, len(data), 8):
        feedback = bf_encrypt_block(key, feedback)
        chunk = data[off:off + 8]
        out.extend(xor_bytes(chunk, feedback[:len(chunk)]))
    return bytes(out)


def ctr_like(key: bytes, data: bytes, counter: int, salt: int, byte_step: bool = False) -> bytes:
    out = bytearray()
    for off in range(0, len(data), 8):
        ctr = counter + (off if byte_step else off // 8)
        ks = bf_encrypt_block(key, block_from_counter(ctr, salt))
        chunk = data[off:off + 8]
        out.extend(xor_bytes(chunk, ks[:len(chunk)]))
    return bytes(out)


def lcg_stream(seed: int, n: int) -> bytes:
    state = seed & 0xFFFFFFFF
    out = bytearray()
    while len(out) < n:
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        out.extend(state.to_bytes(4, "little"))
    return bytes(out[:n])


def rc4_stream(key: bytes, n: int, drop: int = 0) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for idx in range(n + drop):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) & 0xFF]
        if idx >= drop:
            out.append(k)
    return bytes(out)


def apply_model(model: str, data: bytes, base_key: bytes, packet_no: int, c2s_index: int, running_byte: int, state_delta: int, body_offset: int) -> bytes:
    if body_offset >= len(data):
        return data
    key = mutate_key(base_key, state_delta)
    head = data[:body_offset]
    body = data[body_offset:]
    salt = body_offset + (state_delta & 0xFFFF)
    if model == "A_Blowfish_CFB_like":
        dec = cfb_like(key, body, packet_no + state_delta, salt)
    elif model == "B_Blowfish_OFB_like":
        dec = ofb_like(key, body, packet_no + state_delta, salt)
    elif model == "C_Blowfish_CTR_frame_counter":
        dec = ctr_like(key, body, packet_no + state_delta, salt)
    elif model == "D_Blowfish_CTR_c2s_counter":
        dec = ctr_like(key, body, c2s_index + state_delta, salt)
    elif model == "E_Blowfish_CTR_running_byte_counter":
        dec = ctr_like(key, body, running_byte + state_delta, salt, byte_step=True)
    elif model == "F_XORpass_LCG_seed_stream":
        seed = int.from_bytes(key[:4], "little") + packet_no + c2s_index + running_byte + body_offset
        dec = xor_bytes(body, lcg_stream(seed, len(body)))
    elif model == "G_XORpass_plus_packet_counter":
        return public_xorpass(data, mutate_key(base_key, packet_no + c2s_index + state_delta), offset=body_offset, include_prev=True, update_size_before=False)
    elif model == "H_RC4_like_session_stream":
        rc4_key = key + block_from_counter(packet_no + c2s_index + state_delta, running_byte)
        dec = xor_bytes(body, rc4_stream(rc4_key, len(body), drop=body_offset))
    elif model == "M_header_separate_body_transform":
        header = public_xorpass(head, key, offset=0, include_prev=True, update_size_before=False) if head else b""
        dec = ctr_like(key, body, c2s_index + running_byte + state_delta, salt)
        return header + dec
    else:
        raise ValueError(model)
    return head + dec


def utf16_ratio(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    even = data[:len(data) - (len(data) % 2)]
    text = even.decode("utf-16le", errors="ignore")
    if not text:
        return 0.0
    return sum(1 for ch in text if ch.isprintable()) / len(text)


def validate(decoded: bytes, expected: str, body_offset: int) -> dict[str, object]:
    expected_utf16 = expected.encode("utf-16le")
    matched_utf16 = [m for m in TARGET_MESSAGES if m.encode("utf-16le") in decoded]
    matched_ascii = [m for m in TARGET_MESSAGES if m.encode("ascii") in decoded]
    exact_at_body = body_offset < len(decoded) and decoded[body_offset:body_offset + len(expected_utf16)] == expected_utf16
    text_offsets = [off for off in BODY_OFFSETS if off < len(decoded) and decoded[off:off + len(expected_utf16)] == expected_utf16]
    length_le = int.from_bytes(decoded[:2], "little") if len(decoded) >= 2 else -1
    length_sane = len(decoded) == len(expected_utf16) + 10 or 2 <= length_le <= len(decoded) + 32
    opcode_complement = any(len(decoded) > b and decoded[a] == ((~decoded[b]) & 0xFF) for a, b in ((2, 3), (3, 4), (4, 5), (6, 7), (8, 9)))
    return {
        "exact_utf16": expected_utf16 in decoded,
        "exact_utf16_at_body_offset": exact_at_body,
        "text_offset_hits": text_offsets,
        "ascii_secondary": expected.encode("ascii") in decoded,
        "matched_utf16": sorted(set(matched_utf16)),
        "matched_ascii": sorted(set(matched_ascii)),
        "utf16_ratio": utf16_ratio(decoded),
        "length_sane": length_sane,
        "opcode_complement": opcode_complement,
    }


def score(v: dict[str, object], repeat_consistency: bool, multi_match_count: int) -> float:
    return (
        (1000 if v["exact_utf16"] else 0)
        + (250 if v["exact_utf16_at_body_offset"] else 0)
        + (100 if v["ascii_secondary"] else 0)
        + (50 if multi_match_count >= 3 else 0)
        + (25 if repeat_consistency else 0)
        + (10 if v["length_sane"] else 0)
        + (5 if v["opcode_complement"] else 0)
        + float(v["utf16_ratio"])
    )


def safe_prev_summary() -> dict[str, object]:
    summary = {"total_trial_rows": 0, "best_score": 0.0, "best_candidate_label": "", "best_update_rule": "", "best_transform": "", "exact_plaintext_found": False, "any_utf16_structure": False}
    if not PREV_LOCAL.exists():
        return summary
    with PREV_LOCAL.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            summary["total_trial_rows"] = int(summary["total_trial_rows"]) + 1
            try:
                row_score = float(row.get("score", "0") or 0)
            except ValueError:
                row_score = 0.0
            if row_score > float(summary["best_score"]):
                summary["best_score"] = row_score
                summary["best_candidate_label"] = row.get("candidate_label", "")
                summary["best_update_rule"] = row.get("update_rule", "")
                summary["best_transform"] = f"{row.get('transform', '')} offset={row.get('offset', '')}"
            if row.get("exact_utf16") == "yes":
                summary["exact_plaintext_found"] = True
            try:
                if float(row.get("utf16_printable_ratio", "0") or 0) >= 0.80:
                    summary["any_utf16_structure"] = True
            except ValueError:
                pass
    summary["best_score"] = round(float(summary["best_score"]), 3)
    return summary


def has_period(data: bytes, period: int) -> bool:
    return len(data) >= period * 2 and all(data[i] == data[i % period] for i in range(len(data)))


def rolling_xor_consistent(a: bytes, b: bytes) -> bool:
    if len(a) != len(b) or len(a) < 3:
        return False
    diffs = [a[i] ^ b[i] for i in range(len(a))]
    transitions = [diffs[i] ^ diffs[i - 1] for i in range(1, len(diffs))]
    return len(set(transitions)) <= max(2, len(transitions) // 8)


def differential_oracle(payload_a: bytes, payload_b: bytes) -> tuple[list[dict[str, object]], dict[str, object]]:
    rows = []
    identical = payload_a == payload_b
    same_len = len(payload_a) == len(payload_b)
    period_hits: set[int] = set()
    rolling_hits: list[int] = []
    header_body_split_hints = []
    for strip in BODY_OFFSETS:
        aa = payload_a[strip:]
        bb = payload_b[strip:]
        if len(aa) != len(bb):
            continue
        diff = bytes(x ^ y for x, y in zip(aa, bb))
        periods = [p for p in PERIODS if has_period(diff, p)]
        period_hits.update(periods)
        rolling = rolling_xor_consistent(aa, bb)
        if rolling:
            rolling_hits.append(strip)
        header_same = payload_a[:strip] == payload_b[:strip] if strip else identical
        body_same = aa == bb
        if header_same != body_same:
            header_body_split_hints.append(strip)
        rows.append({
            "strip_offset": strip,
            "same_length": same_len,
            "ciphertexts_identical": identical,
            "simple_period_labels": "|".join(str(p) for p in periods) if periods else "none",
            "rolling_xor_consistent": rolling,
            "header_same_body_differs": header_same and not body_same,
            "header_differs_body_same": (not header_same) and body_same,
        })
    return rows, {
        "same_length": same_len,
        "ciphertexts_identical": identical,
        "period_hits": sorted(period_hits),
        "rolling_consistent_offsets": rolling_hits,
        "header_body_split_hints": sorted(set(header_body_split_hints)),
    }


def state_delta_for(mode: str, packet_no: int, pkt: dict[str, object], c2s_before: dict[int, int], bidi_before: dict[int, int], c2s_index: int) -> int:
    if mode == "direct_per_packet":
        return packet_no + c2s_index
    if mode == "sequential_c2s_15":
        return c2s_before.get(packet_no, 0)
    if mode == "bidirectional_state":
        return bidi_before.get(packet_no, 0)
    if mode == "no_update_control":
        return 0
    raise ValueError(mode)


def main() -> None:
    LOCAL_OUT.mkdir(parents=True, exist_ok=True)
    ART.mkdir(parents=True, exist_ok=True)
    INBOX.mkdir(parents=True, exist_ok=True)

    prev = safe_prev_summary()
    packets = tcp_payload_rows(CAPTURE)
    by_packet = {int(row["packet_no"]): row for row in packets}
    target_packets_found = all(packet_no in by_packet for packet_no, _msg in TARGETS)
    world_frame_found = WORLD_SMKEY_FRAME in by_packet
    main_flow = by_packet[WORLD_SMKEY_FRAME]["flow"] if world_frame_found else by_packet[FIRST_MESSAGE_FRAME]["flow"]
    c2s_stream = [row for row in packets if row["flow"] == main_flow and row["direction"] == "C2S" and WORLD_SMKEY_FRAME < int(row["packet_no"]) <= max(TARGET_BY_PACKET) and int(row["payload_len"]) > 0]
    bidi_stream = [row for row in packets if row["flow"] == main_flow and WORLD_SMKEY_FRAME < int(row["packet_no"]) <= max(TARGET_BY_PACKET) and int(row["payload_len"]) > 0]
    c2s_index = {int(row["packet_no"]): idx + 1 for idx, row in enumerate(c2s_stream)}
    running_byte = {}
    total = 0
    c2s_before = {}
    for row in c2s_stream:
        pn = int(row["packet_no"])
        running_byte[pn] = total
        c2s_before[pn] = total
        total += int(row["payload_len"])
    total = 0
    bidi_before = {}
    for row in bidi_stream:
        pn = int(row["packet_no"])
        bidi_before[pn] = total
        total += int(row["payload_len"])
    intermediate_count = len([row for row in c2s_stream if int(row["packet_no"]) < FIRST_MESSAGE_FRAME])

    diff_rows: list[dict[str, object]] = []
    diff_summary = {"same_length": False, "ciphertexts_identical": False, "period_hits": [], "rolling_consistent_offsets": [], "header_body_split_hints": []}
    if all(frame in by_packet for frame in REPEAT_FRAMES):
        diff_rows, diff_summary = differential_oracle(by_packet[REPEAT_FRAMES[0]]["payload"], by_packet[REPEAT_FRAMES[1]]["payload"])
    write_csv(LOCAL_OUT / "stream_diff_oracle_local.csv", diff_rows)

    trials: list[dict[str, object]] = []
    matched: set[str] = set()
    exact_any = False
    best = {"score": -1.0, "candidate_label": "", "stream_model": "", "state_mode": "", "body_offset": None}
    combo_matches: dict[tuple[str, str, str, int], set[str]] = {}
    decoded_cache: dict[tuple[str, str, str, int, int], bytes] = {}

    if target_packets_found:
        for key_label, key in START_KEYS.items():
            for model in STREAM_MODELS:
                for state_mode in STATE_MODES:
                    for body_offset in BODY_OFFSETS:
                        combo = (key_label, model, state_mode, body_offset)
                        combo_matches[combo] = set()
                        for packet_no, expected in TARGETS:
                            pkt = by_packet[packet_no]
                            delta = state_delta_for(state_mode, packet_no, pkt, c2s_before, bidi_before, c2s_index.get(packet_no, 0))
                            decoded = apply_model(model, pkt["payload"], key, packet_no, c2s_index.get(packet_no, 0), running_byte.get(packet_no, 0), delta, body_offset)
                            decoded_cache[(*combo, packet_no)] = decoded
                            v = validate(decoded, expected, body_offset)
                            combo_matches[combo].update(v["matched_utf16"])
        for key_label, key in START_KEYS.items():
            for model in STREAM_MODELS:
                for state_mode in STATE_MODES:
                    for body_offset in BODY_OFFSETS:
                        combo = (key_label, model, state_mode, body_offset)
                        repeat_consistency = decoded_cache.get((*combo, REPEAT_FRAMES[0])) == decoded_cache.get((*combo, REPEAT_FRAMES[1]))
                        multi_match_count = len(combo_matches[combo])
                        for packet_no, expected in TARGETS:
                            decoded = decoded_cache[(*combo, packet_no)]
                            v = validate(decoded, expected, body_offset)
                            matched.update(v["matched_utf16"])
                            exact_any = exact_any or bool(v["exact_utf16"])
                            row_score = score(v, repeat_consistency, multi_match_count)
                            if row_score > float(best["score"]):
                                best = {"score": row_score, "candidate_label": key_label, "stream_model": model, "state_mode": state_mode, "body_offset": body_offset}
                            trials.append({
                                "candidate_label": key_label,
                                "stream_model": model,
                                "state_mode": state_mode,
                                "body_offset": body_offset,
                                "packet_no": packet_no,
                                "expected_label": expected,
                                "exact_utf16": "yes" if v["exact_utf16"] else "no",
                                "exact_utf16_at_body_offset": "yes" if v["exact_utf16_at_body_offset"] else "no",
                                "text_offset_hits": "|".join(str(o) for o in v["text_offset_hits"]),
                                "ascii_secondary": "yes" if v["ascii_secondary"] else "no",
                                "matched_utf16_labels": "|".join(v["matched_utf16"]),
                                "matched_ascii_labels": "|".join(v["matched_ascii"]),
                                "utf16_printable_ratio": f"{float(v['utf16_ratio']):.3f}",
                                "length_sane": "yes" if v["length_sane"] else "no",
                                "opcode_complement": "yes" if v["opcode_complement"] else "no",
                                "repeat_pair_decodes_identically": "yes" if repeat_consistency else "no",
                                "combo_matched_message_count": multi_match_count,
                                "score": f"{row_score:.3f}",
                            })
    write_csv(LOCAL_OUT / "stream_trials_full_local.csv", trials)

    diff_md = [
        "# Pass608 KXSEQ Repeated Plaintext Differential Oracle",
        "",
        "Local-only output. Raw packet bytes, payload hashes, ciphertext XOR bytes, and decoded blobs are intentionally omitted.",
        f"- repeat frames tested: {REPEAT_FRAMES[0]}, {REPEAT_FRAMES[1]}",
        f"- same payload length: {diff_summary['same_length']}",
        f"- ciphertexts identical: {diff_summary['ciphertexts_identical']}",
        f"- simple XOR-difference period hits: {', '.join(str(p) for p in diff_summary['period_hits']) if diff_summary['period_hits'] else '(none)'}",
        f"- rolling-XOR-consistent strip offsets: {', '.join(str(o) for o in diff_summary['rolling_consistent_offsets']) if diff_summary['rolling_consistent_offsets'] else '(none)'}",
        f"- header/body split hint offsets: {', '.join(str(o) for o in diff_summary['header_body_split_hints']) if diff_summary['header_body_split_hints'] else '(none)'}",
    ]
    (LOCAL_OUT / "stream_diff_oracle_local.md").write_text("\n".join(diff_md) + "\n", encoding="utf-8")

    matched_sorted = sorted(matched)
    exact_rows = sum(1 for row in trials if row["exact_utf16"] == "yes")
    local_notes = [
        "# Pass608 KXSEQ Stream Hypotheses Debug Notes",
        "",
        "Detailed output is local-only and intentionally not committed.",
        f"- target packets found: {target_packets_found}",
        f"- world SM_KEY frame found: {world_frame_found}",
        f"- intermediate C2S packets before first message: {intermediate_count}",
        f"- previous local best: {prev['best_candidate_label']} / {prev['best_update_rule']} / {prev['best_transform']} / {prev['best_score']}",
        f"- previous exact plaintext found: {prev['exact_plaintext_found']}",
        f"- previous UTF-16 structure observed: {prev['any_utf16_structure']}",
        f"- models tested: {', '.join(STREAM_MODELS)}",
        f"- state modes tested: {', '.join(STATE_MODES)}",
        f"- stream trial rows: {len(trials)}",
        f"- exact UTF-16LE matches: {exact_rows}",
        f"- matched labels: {', '.join(matched_sorted) if matched_sorted else '(none)'}",
        f"- best candidate: {best['candidate_label']}",
        f"- best stream model: {best['stream_model']}",
        f"- best state mode: {best['state_mode']}",
        f"- best body offset: {best['body_offset']}",
        f"- best score: {float(best['score']):.3f}",
        "- no raw packet payload hex, payload hashes, ciphertext XORs, decrypted prefixes, or decoded byte blobs are written to Git artifacts.",
    ]
    (LOCAL_OUT / "stream_debug_notes_local.md").write_text("\n".join(local_notes) + "\n", encoding="utf-8")

    decision = {
        "worker": "codex",
        "phase": "pass608_kxseq_stream_hypotheses",
        "world_seed": spaced_hex(WORLD_SEED),
        "lobby_seed": spaced_hex(LOBBY_SEED),
        "target_packets_tested": bool(target_packets_found),
        "repeat_plaintext_oracle_tested": bool(diff_rows),
        "stream_hypotheses_tested": bool(trials),
        "body_only_offsets_tested": BODY_ONLY_OFFSETS,
        "sequential_15_packets_tested": "sequential_c2s_15" in STATE_MODES and intermediate_count == 15,
        "bidirectional_state_tested": "bidirectional_state" in STATE_MODES,
        "trial_rows_local_only": len(trials),
        "decoder_success": bool(exact_any),
        "exact_plaintext_recovered": bool(exact_any),
        "matched_messages_count": len(matched_sorted),
        "matched_messages_labels": matched_sorted,
        "best_candidate_label": str(best["candidate_label"]),
        "best_stream_model": f"{best['stream_model']} / {best['state_mode']}",
        "best_body_offset": best["body_offset"],
        "best_score": round(float(best["score"]), 3),
        "raw_payload_committed": False,
        "payload_hash_committed": False,
        "decrypted_blob_committed": False,
        "forbidden_methods_used": False,
        "reason": "Exact KXSEQ plaintext recovered from PCAP." if exact_any else "Expanded RC4/CTR/CFB/OFB/body-only stream hypotheses were tested against the corrected KXSEQ oracle, including sequential and bidirectional state, but no exact UTF-16LE KXSEQ plaintext was recovered.",
        "next_action": "Use file-backed code/decompile/source evidence for the custom game-channel transform, key schedule, stream IV/counter source, or header/body boundary. Do not use live process, debugger, memory dump, injection, anti-cheat bypass, or packet injection.",
    }
    (ART / "pass608_codex_stream_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")

    summary = [
        "# Pass608 Codex KXSEQ Stream Hypotheses Summary",
        "",
        "Git-safe summary only. Detailed differential and trial output stayed local-only under `C:\\AionTools\\aion_decoder_agent\\outbox\\pass608_kxseq_local\\`.",
        "",
        "## Previous Local Sequential Result",
        f"- total trial rows: {prev['total_trial_rows']}",
        f"- best score: {prev['best_score']}",
        f"- best candidate label: `{prev['best_candidate_label']}`",
        f"- best update rule: `{prev['best_update_rule']}`",
        f"- best transform: `{prev['best_transform']}`",
        f"- exact plaintext found: {str(prev['exact_plaintext_found']).lower()}",
        f"- any high UTF-16 printable structure: {str(prev['any_utf16_structure']).lower()}",
        "",
        "## Repeated Plaintext Differential",
        f"- frames tested: {REPEAT_FRAMES[0]}, {REPEAT_FRAMES[1]}",
        f"- same length: {str(diff_summary['same_length']).lower()}",
        f"- ciphertexts identical: {str(diff_summary['ciphertexts_identical']).lower()}",
        f"- simple period labels: {', '.join(str(p) for p in diff_summary['period_hits']) if diff_summary['period_hits'] else '(none)'}",
        f"- rolling-XOR strip offsets: {', '.join(str(o) for o in diff_summary['rolling_consistent_offsets']) if diff_summary['rolling_consistent_offsets'] else '(none)'}",
        f"- header/body split hint offsets: {', '.join(str(o) for o in diff_summary['header_body_split_hints']) if diff_summary['header_body_split_hints'] else '(none)'}",
        "",
        "## Stream Trial Result",
        f"- target packets tested: {str(target_packets_found).lower()}",
        f"- stream models tested: CFB-like, OFB-like, CTR frame, CTR C2S, CTR running-byte, LCG, XORpass counter, RC4-like, header/body separate",
        f"- state modes tested: {', '.join(STATE_MODES)}",
        f"- body/text offsets tested: {', '.join(str(o) for o in BODY_OFFSETS)}",
        f"- local-only trial rows: {len(trials)}",
        f"- exact UTF-16LE KXSEQ matches: {exact_rows}",
        f"- matched message labels: {', '.join(matched_sorted) if matched_sorted else '(none)'}",
        f"- best candidate label: `{best['candidate_label']}`",
        f"- best stream model: `{best['stream_model']}`",
        f"- best state mode: `{best['state_mode']}`",
        f"- best body offset: {best['body_offset']}",
        f"- best score: {float(best['score']):.3f}",
        "",
        "## Git Safety",
        "- raw packet payload committed: false",
        "- payload hash committed: false",
        "- ciphertext XOR committed: false",
        "- decrypted blob/prefix committed: false",
    ]
    (ART / "pass608_codex_stream_summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")

    report = [
        "# Codex Pass608 KXSEQ Stream Hypotheses Report",
        "",
        f"Decision: `{'decoder_success' if exact_any else 'blocked_kxseq_stream_no_plaintext_recovery'}`",
        "",
        f"- repeated KXSEQ_010_REPEAT differential tested: {'yes' if diff_rows else 'no'}",
        "- RC4/CTR/CFB/OFB/body-only models tested: yes",
        f"- exact KXSEQ plaintext recovered: {'yes' if exact_any else 'no'}",
        f"- matched messages: {', '.join(matched_sorted) if matched_sorted else '(none)'}",
        f"- best candidate label: {best['candidate_label']}",
        f"- best stream model/state: {best['stream_model']} / {best['state_mode']}",
        f"- best body offset: {best['body_offset']}",
        f"- best score: {float(best['score']):.3f}",
        "- detailed outputs stayed local-only: yes",
        "- Git contains no raw packet/hash/decrypted data: yes",
        "",
        "No forbidden methods were used. Memory dumps are not recommended.",
    ]
    (INBOX / "codex_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")

    if exact_any:
        out = PRIVATE / "outbox"
        out.mkdir(parents=True, exist_ok=True)
        (out / "decoded_cleartext.txt").write_text("\n".join(matched_sorted) + "\n", encoding="utf-8")
        (out / "decoder_success.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(decision, indent=2))


if __name__ == "__main__":
    main()
