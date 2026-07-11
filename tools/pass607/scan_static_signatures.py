from __future__ import annotations

import json

from common import ART, EURO, STATIC_KEY, ascii_context, classify_file, find_all, hex_context, parse_pe_sections, section_for_offset, sha256, write_csv


PATTERNS = {
    "public_staticKey_exact": STATIC_KEY,
    "public_staticKey_prefix_nKO": b"nKO/WctQ",
    "public_staticKey_tail_q1Ug": b"q1UgZhFMXH?3iI9",
    "key_tail_A1_6C_54_87": bytes.fromhex("a16c5487"),
    "key_tail_87_54_6C_A1": bytes.fromhex("87546ca1"),
    "false_key_0xCD92E4DF_le": bytes.fromhex("dfe492cd"),
    "false_key_0x3FF2CCCF_le": bytes.fromhex("cfccf23f"),
    "false_key_0xCD92E451_le": bytes.fromhex("51e492cd"),
    "false_key_0x3FF2CC87_le": bytes.fromhex("87ccf23f"),
    "false_key_0xCD92E4DF_be": bytes.fromhex("cd92e4df"),
    "false_key_0x3FF2CCCF_be": bytes.fromhex("3ff2cccf"),
    "false_key_0xCD92E451_be": bytes.fromhex("cd92e451"),
    "false_key_0x3FF2CC87_be": bytes.fromhex("3ff2cc87"),
    "mask_i_and_0x3f": bytes.fromhex("83e03f"),
    "mask_i_and_0x7": bytes.fromhex("83e007"),
    "sm_key_ascii": b"SM_KEY",
    "staticKey_ascii": b"staticKey",
    "PacketCrypt_ascii": b"PacketCrypt",
    "clientPacketKey_ascii": b"clientPacketKey",
    "serverPacketKey_ascii": b"serverPacketKey",
    "WSARecv_ascii": b"WSARecv",
    "WSASend_ascii": b"WSASend",
    "recv_ascii": b"recv",
    "send_ascii": b"send",
}


def hit_classification(file_class: str, name: str) -> str:
    if file_class == "Aion4.9_Gamez_public_control":
        return "public_reference"
    if file_class in {"EuroAion_target_primary", "Destiny_or_comparable_target"} and (
        name.startswith("public_staticKey") or name.startswith("false_key") or name.startswith("key_tail")
    ):
        return "EuroAion_candidate"
    if name in {"recv_ascii", "send_ascii", "WSARecv_ascii", "WSASend_ascii"}:
        return "false_positive_import_or_string"
    if file_class == "support_dll":
        return "false_positive_support_library"
    return "context_required"


def main() -> None:
    rows = []
    summary: dict[str, dict[str, int]] = {}
    for path in sorted(p for p in EURO.rglob("*") if p.is_file()):
        data = path.read_bytes()
        file_class = classify_file(path)
        digest = sha256(path)
        sections = parse_pe_sections(data)
        for name, pat in PATTERNS.items():
            for off in find_all(data, pat):
                classification = hit_classification(file_class, name)
                rows.append({
                    "path": str(path),
                    "relative_path": str(path.relative_to(EURO)),
                    "file_classification": file_class,
                    "sha256": digest,
                    "offset_decimal": off,
                    "offset_hex": hex(off),
                    "section": section_for_offset(sections, off),
                    "signature": name,
                    "matched_hex": pat.hex(),
                    "hex_context": hex_context(data, off),
                    "ascii_context": ascii_context(data, off),
                    "classification": classification,
                })
                summary.setdefault(file_class, {}).setdefault(name, 0)
                summary[file_class][name] += 1
    fields = ["path", "relative_path", "file_classification", "sha256", "offset_decimal", "offset_hex", "section", "signature", "matched_hex", "hex_context", "ascii_context", "classification"]
    write_csv(ART / "pass607_codex_static_signature_hits.csv", rows, fields)
    lines = [
        "# Pass607 Codex Static Signature Summary",
        "",
        "Static/offline byte scan only. Import/string presence is not treated as packet-sink proof.",
        "",
        "## Hit Counts",
    ]
    for file_class in sorted(summary):
        lines.append(f"- {file_class}: {json.dumps(summary[file_class], sort_keys=True)}")
    target_crypto_hits = [r for r in rows if r["classification"] == "EuroAion_candidate"]
    lines += [
        "",
        "## Evidence Gate",
        f"- EuroAion/Destiny target crypto-key candidate hits: {len(target_crypto_hits)}",
        "- Public Aion4.9/Gamez hits remain public controls only.",
        "- No packet sink is claimed from send/recv/WSA string/import hits.",
    ]
    (ART / "pass607_codex_static_signature_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"signature rows={len(rows)} target_crypto_hits={len(target_crypto_hits)}")


if __name__ == "__main__":
    main()
