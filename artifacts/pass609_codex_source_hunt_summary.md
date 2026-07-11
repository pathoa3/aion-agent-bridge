# Pass609 Codex Source/Decompile Hunt Summary

Static/offline and public-source only. No live process, debugger, memory dump, injection, anti-cheat bypass, packet injection, or unknown client binary execution was used.

## Result
- new source/decompile candidate found: false
- new decoder variant tested in Pass609: false
- exact plaintext recovered: false
- candidates inventoried: 13
- duplicate public-reference sources: 9
- protected-binary-only leads: 2
- unavailable direct EuroAion/source leads: 1

## Exhausted Categories
- A. Local bridge reports/scripts: searched for SM_KEY, Aion75Mask, NewCrypt, GameCrypt, XORpass, Blowfish, staticKey, Themida, .aion1, VM handler, packet sink, 7785, PacketSamurai, AionEmu, EuroAion, Gamez, Destiny, 4.6, and 4.7.5.
- B. Local private workspace reports: reviewed acquisition, source truthing, static triage, Pass604 binary-static, and old VM handover artifacts without copying private packet data.
- C. Public code/web search: searched Aion 4.6/4.7/4.7.5 packet crypto, SM_KEY, GameCrypt, PacketSamurai, staticKey, XORpass, EuroAion-specific source/decompile terms, and private-server custom crypto terms.
- D. Public repositories: inspected Rydiik/Aion-Server-4.6 PacketSamurai code and compared prior Aion-unique, aion-proxy, WorldEncryption.cpp, AION-SERVER, AionGermany, and AionLightning lineage reports.
- E. Binary/static local evidence: rechecked existing Pass604/Pass598 conclusions; no broad binary rescan was run.
- F. Candidate expansion: no genuinely new algorithm candidate was found, so no Pass609 decoder variant was generated.

## Public Source Findings
- Rydiik/Aion-Server-4.6 `AionGameCrypter.java`: public staticKey rolling XOR, previous-byte chaining, key += raw length; duplicate public reference.
- Rydiik `AionGame4_5_0_15Crypter.java`: only opcode/static packet-code constants differ; no new payload transform.
- Rydiik `NewCrypt.java`: public Blowfish/XORpass/checksum helper; duplicate public reference/login-style helper.
- Rydiik `AL-Login CryptEngine.java`: login-channel Blowfish/XORpass, irrelevant to 7785 game-channel transform.
- aion-proxy shifted-offset source was already tested in Pass601 and recovered no exact oracle matches.

## Best Remaining Lead
The only meaningful remaining static path is the protected `.aion1` VM edge already identified locally: prove or reject the bridge from RSI/RBX VM context to the block around `0x114731E0..0x114731F5`, then to packet buffer/length/text-byte source and transform writes. The alternative is a legitimate unpacked/less-protected 4.6/4.7.5 comparator or exact custom source/decompile evidence.

## Git Safety
- private packet payload committed: false
- private payload hashes committed: false
- raw binary committed: false
- decoded byte blobs committed: false
- full private trial CSV committed: false

## Search Terms
`SM_KEY`, `Aion75Mask`, `NewCrypt`, `GameCrypt`, `XORpass`, `Blowfish`, `staticKey`, `key schedule`, `aion1`, `Themida`, `VM handler`, `virtualized`, `packet sink`, `7785`, `PacketSamurai`, `AionEmu`, `EuroAion`, `Gamez`, `Destiny`, `4.6`, `4.7.5`, `Aion 4.6 packet encryption`, `Aion 4.7 packet encryption`, `Aion client packet decrypt`, `Aion private server custom crypt`, `Aion opcode complement`, `Aion packet length UTF-16`
