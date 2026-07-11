from __future__ import annotations

from pass607_codex_startup_common import ART, EXPECTED_SMKEY, MASK7, PACKET9740_HEX, SEED, STARTUP_PCAP, spaced_hex, tcp_payload_rows, write_csv, xor_first_then_tail, xor_repeat


def main() -> None:
    packets = tcp_payload_rows(STARTUP_PCAP)
    p9740 = next((r for r in packets if int(r["packet_no"]) == 9740), None)
    pmatch = next((r for r in packets if r["payload"] == bytes.fromhex(PACKET9740_HEX)), None)
    payload_cases = [("requested_packet_9740", p9740["payload"] if p9740 else b"", p9740)]
    if pmatch and (not p9740 or int(pmatch["packet_no"]) != int(p9740["packet_no"])):
        payload_cases.append(("matching_antigravity_ciphertext", pmatch["payload"], pmatch))
    rows = []

    def add(case: str, packet_row, payload: bytes, name: str, decoded: bytes, expected: bytes, notes: str) -> None:
        rows.append({
            "case": case,
            "test": name,
            "packet_no": packet_row["packet_no"] if packet_row else "",
            "flow": packet_row["flow"] if packet_row else "",
            "direction": packet_row["direction"] if packet_row else "",
            "input_hex": payload.hex(),
            "mask_hex": MASK7.hex(),
            "decoded_hex": decoded.hex(),
            "decoded_spaced_hex": spaced_hex(decoded),
            "expected_hex": expected.hex(),
            "exact_match": "yes" if decoded == expected else "no",
            "prefix_match": "yes" if decoded[:7] == EXPECTED_SMKEY[:7] else "no",
            "seed_hex": decoded[7:11].hex() if len(decoded) >= 11 else "",
            "notes": notes,
        })

    for case, payload, packet_row in payload_cases:
        add(case, packet_row, payload, "mask_repeats_every_7_bytes", xor_repeat(payload, MASK7), EXPECTED_SMKEY, "Full packet XORed with 7-byte repeating mask.")
        first7 = xor_first_then_tail(payload, MASK7)
        add(case, packet_row, payload, "mask_only_first_7_seed_plain", first7, EXPECTED_SMKEY, "Only first 7 bytes XORed; tail left as captured bytes.")
        add(case, packet_row, payload, "mask_repeat_reversed_seed_expected", xor_repeat(payload, MASK7), EXPECTED_SMKEY[:7] + SEED[::-1], "Same repeated-mask decode compared with reversed seed order.")

    anchor = pmatch or p9740
    same_flow = [r for r in packets if anchor and r["flow"] == anchor["flow"] and r["direction"] == anchor["direction"]]
    stream = b"".join(r["payload"] for r in same_flow)
    start = 0
    if anchor:
        before = b""
        for r in same_flow:
            if int(r["packet_no"]) == int(anchor["packet_no"]):
                break
            before += r["payload"]
        start = len(before)
    for shift in range(-4, 5):
        pos = start + shift
        if pos < 0 or pos + 11 > len(stream):
            decoded = b""
            window = b""
            notes = "shift outside assembled same-direction stream"
        else:
            window = stream[pos:pos + 11]
            decoded = xor_repeat(window, MASK7)
            notes = f"11-byte window at same-direction stream offset {pos}; shift={shift}"
        rows.append({
            "case": "matching_flow_shift_window",
            "test": f"shift_{shift:+d}_mask_repeats_every_7",
            "packet_no": anchor["packet_no"] if anchor else "",
            "flow": anchor["flow"] if anchor else "",
            "direction": anchor["direction"] if anchor else "",
            "input_hex": window.hex(),
            "mask_hex": MASK7.hex(),
            "decoded_hex": decoded.hex(),
            "decoded_spaced_hex": spaced_hex(decoded),
            "expected_hex": EXPECTED_SMKEY.hex(),
            "exact_match": "yes" if decoded == EXPECTED_SMKEY else "no",
            "prefix_match": "yes" if decoded[:7] == EXPECTED_SMKEY[:7] else "no",
            "seed_hex": decoded[7:11].hex() if len(decoded) >= 11 else "",
            "notes": notes,
        })

    write_csv(ART / "pass607_codex_smkey_test.csv", rows)
    exact = [r for r in rows if r["exact_match"] == "yes"]
    md = [
        "# Pass607 Codex SM_KEY Test",
        "",
        f"- requested packet 9740 payload: `{spaced_hex(p9740['payload']) if p9740 else '(not found)'}`",
        f"- matching Antigravity ciphertext packet: `{pmatch['packet_no'] if pmatch else '(not found)'}`",
        f"- candidate mask: `{spaced_hex(MASK7)}`",
        f"- expected plaintext: `{spaced_hex(EXPECTED_SMKEY)}`",
        f"- exact tests matching expected SM_KEY: {len(exact)}",
        f"- repeated 7-byte mask confirms assumption on matching ciphertext: {'yes' if any(r['case'] == 'matching_antigravity_ciphertext' and r['test'] == 'mask_repeats_every_7_bytes' and r['exact_match'] == 'yes' for r in rows) else 'no'}",
        "- no decoder success is claimed by SM_KEY recovery alone.",
    ]
    (ART / "pass607_codex_smkey_test.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"smkey tests={len(rows)} exact={len(exact)}")


if __name__ == "__main__":
    main()
