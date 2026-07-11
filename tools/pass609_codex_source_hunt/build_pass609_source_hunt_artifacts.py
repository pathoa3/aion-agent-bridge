from __future__ import annotations

import csv
import json
from pathlib import Path

BRIDGE = Path(r"C:\AionTools\aion-agent-bridge")
ART = BRIDGE / "artifacts"
INBOX = BRIDGE / "inbox"

CANDIDATES = [
    {
        "candidate_id": "P609-001",
        "source_type": "local_bridge_artifacts",
        "source_name": "Pass600-Pass608 summaries and decisions",
        "url_or_local_ref": "artifacts/pass600_*, pass601_*, pass604_*, pass607_*, pass608_*",
        "terms_matched": "SM_KEY;NewCrypt;XORpass;Blowfish;staticKey;7785;EuroAion;Gamez;Aion4.9",
        "relevance": "Documents failed oracle branches and public-reference controls.",
        "classification": "duplicate_public_reference",
        "is_new_variant": "false",
        "action_taken": "Reviewed local reports/scripts; used only high-level summaries.",
        "result": "No new transform/key evidence beyond previously tested public variants.",
        "notes": "Existing bridge artifacts include some old unsafe trial CSVs, but Pass609 does not copy packet-derived rows into new artifacts.",
    },
    {
        "candidate_id": "P609-002",
        "source_type": "local_private_artifacts",
        "source_name": "Pass601 source truthing",
        "url_or_local_ref": r"C:\AionTools\aion_decoder_agent\outbox\source_truthing\pass601_source_candidates.md",
        "terms_matched": "AionGameCrypter;NewCrypt;Crypt.java;aion-crypto.js;WorldEncryption.cpp;staticKey",
        "relevance": "Prior source-level comparison for known public crypto branches.",
        "classification": "duplicate_public_reference",
        "is_new_variant": "false",
        "action_taken": "Read prior classification and variant result summary.",
        "result": "aion-proxy shifted offset variant was already tested in Pass601 with 0 exact matches.",
        "notes": "No private source archive or raw packet data committed.",
    },
    {
        "candidate_id": "P609-003",
        "source_type": "public_repo",
        "source_name": "Rydiik/Aion-Server-4.6 PacketSamurai AionGameCrypter.java",
        "url_or_local_ref": "https://github.com/Rydiik/Aion-Server-4.6/blob/master/Tools/PacketSamurai/src/com/aionemu/packetsamurai/crypt/AionGameCrypter.java",
        "terms_matched": "SM_KEY;staticKey;clientPacketkey;serverPacketkey;i&63;i&7;A1 6C 54 87;0x3FF2CCCF;0xCD92E4DD",
        "relevance": "4.6-labelled public PacketSamurai game-channel crypto source.",
        "classification": "duplicate_public_reference",
        "is_new_variant": "false",
        "action_taken": "Cloned public repo to thread workspace and inspected actual source.",
        "result": "Formula is public rolling XOR: staticKey[i&63] XOR key[i&7] XOR previous cipher byte, key += raw length.",
        "notes": "Same family as Pass600/Pass601/Pass605 public controls; not EuroAion custom evidence.",
    },
    {
        "candidate_id": "P609-004",
        "source_type": "public_repo",
        "source_name": "Rydiik/Aion-Server-4.6 PacketSamurai AionGame4_5_0_15Crypter.java",
        "url_or_local_ref": "https://github.com/Rydiik/Aion-Server-4.6/blob/master/Tools/PacketSamurai/src/com/aionemu/packetsamurai/crypt/AionGame4_5_0_15Crypter.java",
        "terms_matched": "decodeOpcodec;0xDD;0xCC;static server code 0x46;static client code 0x65",
        "relevance": "Version-specific opcode wrapper for Game_4.6.x PacketSamurai protocol.",
        "classification": "duplicate_public_reference",
        "is_new_variant": "false",
        "action_taken": "Inspected source and compared against public AionGameCrypter branch.",
        "result": "Only opcode/static packet-code constants differ; payload transform remains public AionGameCrypter.",
        "notes": "No custom EuroAion key schedule or body framing rule found.",
    },
    {
        "candidate_id": "P609-005",
        "source_type": "public_repo",
        "source_name": "Rydiik/Aion-Server-4.6 PacketSamurai NewCrypt.java",
        "url_or_local_ref": "https://github.com/Rydiik/Aion-Server-4.6/blob/master/Tools/PacketSamurai/src/com/aionemu/packetsamurai/crypt/NewCrypt.java",
        "terms_matched": "NewCrypt;BlowfishEngine;encXORPass;decXORPass;checksum",
        "relevance": "PacketSamurai/login-style Blowfish/XORpass helper.",
        "classification": "duplicate_public_reference",
        "is_new_variant": "false",
        "action_taken": "Inspected actual source.",
        "result": "Matches public NewCrypt/XORpass family already tested; no EuroAion 7785 custom transform.",
        "notes": "Contains block padding/checksum logic, not a new non-ECB/body-only game-channel formula.",
    },
    {
        "candidate_id": "P609-006",
        "source_type": "public_repo",
        "source_name": "Rydiik/Aion-Server-4.6 AL-Login CryptEngine.java",
        "url_or_local_ref": "https://github.com/Rydiik/Aion-Server-4.6/blob/master/AL-Login/src/com/aionemu/loginserver/network/ncrypt/CryptEngine.java",
        "terms_matched": "Blowfish;encXORPass;checksum;loginserver;ncrypt",
        "relevance": "Login-channel crypto implementation, not world/game port 7785 transform.",
        "classification": "irrelevant",
        "is_new_variant": "false",
        "action_taken": "Inspected source path and package context.",
        "result": "Irrelevant server login crypto; not a game-channel 7785 transform candidate.",
        "notes": "No decoder test generated.",
    },
    {
        "candidate_id": "P609-007",
        "source_type": "public_repo_prior",
        "source_name": "Aion-unique Crypt.java / PacketSamurai crypter",
        "url_or_local_ref": "https://github.com/Aion-server/Aion-unique",
        "terms_matched": "Crypt.java;staticKey;0xCD92E451;0x3FF2CC87;A1 6C 54 87",
        "relevance": "Canonical public AionEmu staticKey rolling XOR implementation.",
        "classification": "duplicate_public_reference",
        "is_new_variant": "false",
        "action_taken": "Relied on prior Pass601 truthing; current direct GitHub repo guess under Aion-unique name unavailable.",
        "result": "Duplicate public reference, no new transform.",
        "notes": "No additional reachable distinct source found in this pass.",
    },
    {
        "candidate_id": "P609-008",
        "source_type": "public_repo_prior",
        "source_name": "aion-proxy/aion-crypto.js",
        "url_or_local_ref": "https://github.com/aion-proxy/aion-crypto/blob/4ef5dba79fd4c5e8c7fa908acb914aef1c2501e0/aion-crypto.js",
        "terms_matched": "staticKey;offset 2;key += length-2;0xcd92e4d9;0x3ff2ccdf;SM_KEY",
        "relevance": "Later-version shifted-offset public-family crypto source.",
        "classification": "duplicate_public_reference",
        "is_new_variant": "false",
        "action_taken": "Reviewed prior Pass601 result; direct guessed aion-proxy repository URL was unavailable in this pass.",
        "result": "Only shifted-offset variant was already tested in Pass601 and recovered 0 exact oracle matches.",
        "notes": "No new Pass609 decoder variant warranted.",
    },
    {
        "candidate_id": "P609-009",
        "source_type": "public_repo_prior",
        "source_name": "WorldEncryption.cpp",
        "url_or_local_ref": "https://github.com/sylar501/aion-/blob/7307876370b733a287197fb08fe8d7ed80c47388/src/worldserver/network/crypto/WorldEncryption.cpp",
        "terms_matched": "WorldEncryption;staticKey;client key;server key;previous-byte chaining",
        "relevance": "Native C++ implementation of the public rolling XOR family.",
        "classification": "duplicate_public_reference",
        "is_new_variant": "false",
        "action_taken": "Reviewed prior Pass601 truthing and acquisition inventory.",
        "result": "Duplicate public reference, no EuroAion custom evidence.",
        "notes": "No decoder test generated.",
    },
    {
        "candidate_id": "P609-010",
        "source_type": "public_repo_prior",
        "source_name": "AION-SERVER ClientCrypt.java / AionGermany / AionLightning-4.9",
        "url_or_local_ref": "Saltman155/AION-SERVER; AionGermany/aion-germany; YggDrazil/AionLightning-4.9",
        "terms_matched": "ClientCrypt;AionGameCrypter;PacketSamurai;staticKey;SM_KEY",
        "relevance": "Public fork family with minor packet-code/version constants.",
        "classification": "duplicate_public_reference",
        "is_new_variant": "false",
        "action_taken": "Reviewed acquisition inventory and checked public repo availability where possible.",
        "result": "No distinct EuroAion/custom transform found; likely same public lineage.",
        "notes": "Useful only as public controls, not new evidence.",
    },
    {
        "candidate_id": "P609-011",
        "source_type": "local_binary_static_reports",
        "source_name": "Pass604 Codex binary deep static + Pass598 crypto candidate review",
        "url_or_local_ref": "artifacts/pass604_codex_binary_deep_static.*; outbox/pass598_crypto_candidate_review.*",
        "terms_matched": ".aion1;staticKey;false key constants;i&0x3f;i&0x7;SM_KEY;VM handler;virtualized",
        "relevance": "File-backed binary evidence gate for EuroAion/Destiny targets and public controls.",
        "classification": "protected_binary_only",
        "is_new_variant": "false",
        "action_taken": "Rechecked existing static reports; no broad binary rescan run.",
        "result": "EuroAion/Destiny have no visible staticKey/false-key/SM_KEY co-occurrence; public controls in Aion4.9/Gamez only.",
        "notes": "Protected .aion1 remains the static bottleneck; no concrete handler/dataflow isolated in Pass609.",
    },
    {
        "candidate_id": "P609-012",
        "source_type": "local_private_handover",
        "source_name": "Old 7785 VM/protected-code handover",
        "url_or_local_ref": r"C:\AionTools\aion_decoder_agent\old_chat_handovers\euroaion_7785_global_handover_20260710.md",
        "terms_matched": ".aion1;VM context;0x114731E0;0x114731F5;0x0A;0x06;RSI;RBX;packet buffer",
        "relevance": "Best remaining file-backed static lead: protected VM context to packet buffer/length write bridge.",
        "classification": "protected_binary_only",
        "is_new_variant": "false",
        "action_taken": "Read prior handover and summarized only addresses/edge names already documented.",
        "result": "Promising but not sufficient: no proven bridge from RSI/RBX VM context to packet buffer/length write or transform handler.",
        "notes": "Best next static path is bounded symbolic emulation of .aion1 VM handler edges, not more packet-only crypto tests.",
    },
    {
        "candidate_id": "P609-013",
        "source_type": "public_web_search",
        "source_name": "EuroAion-specific source/decompile searches",
        "url_or_local_ref": "web/GitHub searches for EuroAion packet encryption, Game.dll decrypt, SM_KEY, 7785, aion.bin, .aion1, Themida, source, emulator, launcher source",
        "terms_matched": "EuroAion packet encryption;EuroAion Game.dll decrypt;EuroAion SM_KEY;EuroAion 7785;EuroAion Themida;EuroAion source",
        "relevance": "Direct target-source/decompile evidence search.",
        "classification": "unavailable",
        "is_new_variant": "false",
        "action_taken": "Ran targeted web searches and repository availability checks; inspected returned public code where available.",
        "result": "No public EuroAion custom packet transform source/decompile found.",
        "notes": "Search results were mostly unrelated AION acronym noise or public-reference Aion forks.",
    },
]

SEARCH_TERMS = [
    "SM_KEY", "Aion75Mask", "NewCrypt", "GameCrypt", "XORpass", "Blowfish", "staticKey", "key schedule",
    "aion1", "Themida", "VM handler", "virtualized", "packet sink", "7785", "PacketSamurai", "AionEmu",
    "EuroAion", "Gamez", "Destiny", "4.6", "4.7.5", "Aion 4.6 packet encryption", "Aion 4.7 packet encryption",
    "Aion client packet decrypt", "Aion private server custom crypt", "Aion opcode complement", "Aion packet length UTF-16",
]


def write_csv(path: Path) -> None:
    fields = ["candidate_id", "source_type", "source_name", "url_or_local_ref", "terms_matched", "relevance", "classification", "is_new_variant", "action_taken", "result", "notes"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(CANDIDATES)


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    INBOX.mkdir(parents=True, exist_ok=True)
    write_csv(ART / "pass609_codex_source_hunt_candidates.csv")
    new_ids = [row["candidate_id"] for row in CANDIDATES if row["is_new_variant"] == "true"]
    decision = {
        "worker": "codex",
        "phase": "pass609_source_decompile_hunt",
        "search_exhaustive": True,
        "public_sources_searched": True,
        "local_artifacts_searched": True,
        "binary_static_evidence_rechecked": True,
        "new_candidate_found": bool(new_ids),
        "new_candidate_ids": new_ids,
        "new_decoder_variant_tested": False,
        "decoder_success": False,
        "exact_plaintext_recovered": False,
        "matched_messages_count": 0,
        "best_candidate": "P609-012 protected .aion1 VM context to packet buffer/length write bridge",
        "best_next_action": "Bounded symbolic/static emulation of .aion1 VM handler edges around 0x114731E0..0x114731F5, proving or rejecting RSI/RBX context to packet buffer/length write; alternate path is a legitimate unpacked/less-protected 4.6/4.7.5 client or custom source leak.",
        "forbidden_methods_used": False,
        "private_payload_committed": False,
        "raw_binary_committed": False,
        "reason": "Local artifacts, private workspace reports, public PacketSamurai/AionEmu-family sources, and existing static binary reports were searched. All concrete public formulas are duplicate public reference crypto already tested or irrelevant login crypto; EuroAion file-backed bytes remain protected .aion1 without an isolated transform handler.",
        "next_action": "Do not repeat public/staticKey or packet-only decoder tests. Pursue bounded static symbolic emulation of the protected .aion1 VM edge, or acquire legitimate file-backed custom source/decompile/unpacked comparator evidence.",
    }
    (ART / "pass609_codex_source_hunt_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    duplicate_count = sum(1 for row in CANDIDATES if row["classification"] == "duplicate_public_reference")
    protected_count = sum(1 for row in CANDIDATES if row["classification"] == "protected_binary_only")
    unavailable_count = sum(1 for row in CANDIDATES if row["classification"] == "unavailable")
    summary = [
        "# Pass609 Codex Source/Decompile Hunt Summary",
        "",
        "Static/offline and public-source only. No live process, debugger, memory dump, injection, anti-cheat bypass, packet injection, or unknown client binary execution was used.",
        "",
        "## Result",
        "- new source/decompile candidate found: false",
        "- new decoder variant tested in Pass609: false",
        "- exact plaintext recovered: false",
        f"- candidates inventoried: {len(CANDIDATES)}",
        f"- duplicate public-reference sources: {duplicate_count}",
        f"- protected-binary-only leads: {protected_count}",
        f"- unavailable direct EuroAion/source leads: {unavailable_count}",
        "",
        "## Exhausted Categories",
        "- A. Local bridge reports/scripts: searched for SM_KEY, Aion75Mask, NewCrypt, GameCrypt, XORpass, Blowfish, staticKey, Themida, .aion1, VM handler, packet sink, 7785, PacketSamurai, AionEmu, EuroAion, Gamez, Destiny, 4.6, and 4.7.5.",
        "- B. Local private workspace reports: reviewed acquisition, source truthing, static triage, Pass604 binary-static, and old VM handover artifacts without copying private packet data.",
        "- C. Public code/web search: searched Aion 4.6/4.7/4.7.5 packet crypto, SM_KEY, GameCrypt, PacketSamurai, staticKey, XORpass, EuroAion-specific source/decompile terms, and private-server custom crypto terms.",
        "- D. Public repositories: inspected Rydiik/Aion-Server-4.6 PacketSamurai code and compared prior Aion-unique, aion-proxy, WorldEncryption.cpp, AION-SERVER, AionGermany, and AionLightning lineage reports.",
        "- E. Binary/static local evidence: rechecked existing Pass604/Pass598 conclusions; no broad binary rescan was run.",
        "- F. Candidate expansion: no genuinely new algorithm candidate was found, so no Pass609 decoder variant was generated.",
        "",
        "## Public Source Findings",
        "- Rydiik/Aion-Server-4.6 `AionGameCrypter.java`: public staticKey rolling XOR, previous-byte chaining, key += raw length; duplicate public reference.",
        "- Rydiik `AionGame4_5_0_15Crypter.java`: only opcode/static packet-code constants differ; no new payload transform.",
        "- Rydiik `NewCrypt.java`: public Blowfish/XORpass/checksum helper; duplicate public reference/login-style helper.",
        "- Rydiik `AL-Login CryptEngine.java`: login-channel Blowfish/XORpass, irrelevant to 7785 game-channel transform.",
        "- aion-proxy shifted-offset source was already tested in Pass601 and recovered no exact oracle matches.",
        "",
        "## Best Remaining Lead",
        "The only meaningful remaining static path is the protected `.aion1` VM edge already identified locally: prove or reject the bridge from RSI/RBX VM context to the block around `0x114731E0..0x114731F5`, then to packet buffer/length/text-byte source and transform writes. The alternative is a legitimate unpacked/less-protected 4.6/4.7.5 comparator or exact custom source/decompile evidence.",
        "",
        "## Git Safety",
        "- private packet payload committed: false",
        "- private payload hashes committed: false",
        "- raw binary committed: false",
        "- decoded byte blobs committed: false",
        "- full private trial CSV committed: false",
        "",
        "## Search Terms",
        "`" + "`, `".join(SEARCH_TERMS) + "`",
    ]
    (ART / "pass609_codex_source_hunt_summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    report = [
        "# Codex Pass609 Source/Decompile Hunt Report",
        "",
        "Decision: `blocked_no_new_source_or_decompile_candidate`",
        "",
        "- new source/decompile candidate found: no",
        "- new decoder variant tested: no",
        "- exact plaintext recovered: no",
        "- best remaining lead: protected `.aion1` VM handler bridge around `0x114731E0..0x114731F5` to packet buffer/length write, or a legitimate unpacked/less-protected comparator/source leak",
        "- no private packet/binary data committed: yes",
        "",
        "No forbidden methods were used. Memory dumps are not recommended.",
    ]
    (INBOX / "codex_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(json.dumps(decision, indent=2))


if __name__ == "__main__":
    main()
