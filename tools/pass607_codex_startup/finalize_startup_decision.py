from __future__ import annotations

from pass607_codex_startup_common import ART, INBOX, MASK7, SEED, json_write, read_csv, spaced_hex


def main() -> None:
    verify = read_csv(ART / "pass607_codex_startup_packet9740_verify.csv")
    smkey = read_csv(ART / "pass607_codex_smkey_test.csv")
    trials = read_csv(ART / "pass607_codex_startup_key_trials.csv")
    pass574 = read_csv(ART / "pass607_codex_pass574_oracle_recheck.csv")
    requested = next((r for r in verify if r.get("row_type") == "requested_packet_9740"), verify[0] if verify else {})
    matching = next((r for r in verify if r.get("row_type") == "matching_antigravity_ciphertext"), {})
    tested_packet9740 = bool(requested and requested.get("packet_exists") == "yes")
    packet9740_matches = bool(requested and requested.get("matches_antigravity_hex") == "yes")
    matching_ciphertext_found = bool(matching and matching.get("matches_antigravity_hex") == "yes")
    smkey_ok = any(r.get("case") == "matching_antigravity_ciphertext" and r.get("test") == "mask_repeats_every_7_bytes" and r.get("exact_match") == "yes" for r in smkey)
    marker_matches = sorted({m for r in trials for m in r.get("matched_messages", "").split("|") if m})
    exact_recovered = False
    partial = bool(marker_matches)
    decoder_success = exact_recovered
    startup_key_useful = smkey_ok and partial
    blowfish_unavailable = any(r.get("status") == "not_run_blowfish_library_unavailable" for r in trials)
    pass574_ok = all(r.get("length_model_ok") == "yes" for r in pass574) and len(pass574) == 15
    reason = (
        "The exact Antigravity ciphertext is not at parsed packet 9740; packet 9740 has no payload in a different flow. "
        "The same ciphertext is present at parsed packet 9741 on flow 59085, and the repeated 7-byte SM_KEY mask hypothesis is confirmed there. "
        f"Startup key trials did not recover exact known plaintext. Pass574 oracle recheck length model ok={pass574_ok}. "
        "Blowfish-required rows were recorded as unavailable because no offline Blowfish provider is installed; XORpass-only rows found no markers."
        if smkey_ok else
        "Packet 9740 SM_KEY assumption was not confirmed."
    )
    decision = {
        "worker": "codex",
        "tested_antigravity_packet9740": tested_packet9740,
        "smkey_assumption_confirmed": smkey_ok,
        "candidate_seed": spaced_hex(SEED),
        "candidate_mask": spaced_hex(MASK7),
        "decoder_success": decoder_success,
        "partial_oracle_recovery": partial,
        "startup_key_useful": startup_key_useful,
        "exact_plaintext_recovered": exact_recovered,
        "matched_messages": marker_matches,
        "forbidden_methods_used": False,
        "reason": reason,
        "next_action": "Provide a file-backed/offline Blowfish-capable decoder implementation or source/decompile for the startup game-channel transform; do not use memory dumps, attach/debug, live process, injection, anti-cheat bypass, or packet injection.",
    }
    json_write(ART / "pass607_codex_startup_decision.json", decision)
    final = [
        "# Pass607 Codex Startup Hypothesis Test",
        "",
        "## Boundary",
        "Static/offline PCAP and script analysis only. No client binary was run, no live process was attached/debugged, no memory dump was used, and no packet injection was performed.",
        "",
        "## Packet 9740",
        f"- requested packet 9740 exists: {'yes' if tested_packet9740 else 'no'}",
        f"- requested packet 9740 matches Antigravity hex: {'yes' if packet9740_matches else 'no'}",
        f"- requested packet 9740 flow: {requested.get('flow', '')}",
        f"- requested packet 9740 direction: {requested.get('direction', '')}",
        f"- requested packet 9740 raw length: {requested.get('raw_payload_length', '')}",
        f"- matching ciphertext found elsewhere: {'yes' if matching_ciphertext_found else 'no'}",
        f"- matching packet: {matching.get('packet_no', '')}",
        f"- matching flow: {matching.get('flow', '')}",
        f"- matching direction: {matching.get('direction', '')}",
        f"- matching raw length: {matching.get('raw_payload_length', '')}",
        "",
        "## SM_KEY",
        f"- candidate mask: `{spaced_hex(MASK7)}`",
        f"- candidate seed: `{spaced_hex(SEED)}`",
        f"- repeated 7-byte mask yields exact `0B 00 F9 01 56 06 FE 39 90 C5 A2` on matching ciphertext: {'yes' if smkey_ok else 'no'}",
        "",
        "## Startup Key Trials",
        f"- trial rows: {len(trials)}",
        f"- marker matches: {len(marker_matches)}",
        f"- Blowfish provider unavailable: {'yes' if blowfish_unavailable else 'no'}",
        "- decoder_success remains false because no exact known plaintext was recovered from PCAP.",
        "",
        "## Pass574 Recheck",
        f"- rows: {len(pass574)}",
        f"- all raw lengths equal UTF-16LE + 10: {'yes' if pass574_ok else 'no'}",
        "",
        "## Decision",
        f"- decision: {'decoder_success' if decoder_success else 'blocked_startup_key_not_plaintext_validated'}",
        f"- reason: {reason}",
    ]
    (ART / "pass607_codex_startup_final.md").write_text("\n".join(final) + "\n", encoding="utf-8")
    report = [
        "# Codex Pass607 Startup Report",
        "",
        f"Decision: `{'decoder_success' if decoder_success else 'blocked_startup_key_not_plaintext_validated'}`",
        "",
        f"- packet 9740 exists: {'yes' if tested_packet9740 else 'no'}",
        f"- packet 9740 contains claimed ciphertext: {'yes' if packet9740_matches else 'no'}",
        f"- claimed ciphertext found at packet {matching.get('packet_no', '(not found)')}: {'yes' if matching_ciphertext_found else 'no'}",
        f"- SM_KEY repeated-mask assumption confirmed on matching ciphertext: {'yes' if smkey_ok else 'no'}",
        f"- candidate seed: `{spaced_hex(SEED)}`",
        f"- candidate mask: `{spaced_hex(MASK7)}`",
        f"- startup key useful for plaintext recovery: {'yes' if startup_key_useful else 'no'}",
        f"- exact plaintext recovered: {'yes' if exact_recovered else 'no'}",
        f"- matched messages: {', '.join(marker_matches) if marker_matches else '(none)'}",
        f"- Pass574 UTF-16LE + 10 recheck: {'yes' if pass574_ok else 'no'}",
        "",
        "No forbidden methods were used. No decoder success is claimed.",
    ]
    INBOX.mkdir(parents=True, exist_ok=True)
    (INBOX / "codex_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(decision)


if __name__ == "__main__":
    main()
