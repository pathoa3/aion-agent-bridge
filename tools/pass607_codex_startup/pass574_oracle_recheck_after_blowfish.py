from __future__ import annotations

import hashlib

from pass607_codex_startup_common import ART, PASS574_LOG, PASS574_PCAP, parse_log_messages, tcp_payload_rows, write_csv


def main() -> None:
    messages = parse_log_messages(PASS574_LOG)
    c2s = [r for r in tcp_payload_rows(PASS574_PCAP) if r["direction"] == "C2S" and int(r["payload_len"]) > 0]
    rows = []
    search_pos = 0
    for idx, msg in enumerate(messages, 1):
        utf16_len = len(msg.encode("utf-16le"))
        expected = utf16_len + 10
        found = None
        for pos in range(search_pos, len(c2s)):
            r = c2s[pos]
            if int(r["packet_no"]) < 7166:
                continue
            if int(r["payload_len"]) == expected:
                found = (pos, r)
                break
        if not found:
            rows.append({
                "oracle_index": idx,
                "message": msg,
                "expected_utf16le_len": utf16_len,
                "expected_raw_len_utf16_plus_10": expected,
                "packet_no": "",
                "raw_payload_len": "",
                "length_model_ok": "no",
                "payload_sha256": "",
                "raw_payload_hex": "",
            })
            continue
        pos, r = found
        search_pos = pos + 1
        payload = r["payload"]
        rows.append({
            "oracle_index": idx,
            "message": msg,
            "expected_utf16le_len": utf16_len,
            "expected_raw_len_utf16_plus_10": expected,
            "packet_no": r["packet_no"],
            "raw_payload_len": len(payload),
            "length_model_ok": "yes" if len(payload) == expected else "no",
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "raw_payload_hex": payload.hex(),
        })
    write_csv(ART / "pass607_codex_pass574_oracle_recheck_after_blowfish.csv", rows)
    print(f"pass574 rows={len(rows)} all_ok={all(r['length_model_ok'] == 'yes' for r in rows)}")


if __name__ == "__main__":
    main()
