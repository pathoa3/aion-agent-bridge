# Pass604 Deep Static Binary Grind

## Scope & Objective
This document summarizes the Pass604 static PE and binary evaluation conducted offline/statically on files within `inbox/euroaion` to recover the game-channel (port 7785) packet transform and decrypt schedule.

## Evaluated Binaries & Signatures

### 1. EuroAion Client Core (`game.dll` & `aion.bin`)
- **Path:** `inbox/euroaion/Aion/EuroAion/game.dll`
- **Hash:** `c4b5ad116928685c0cd443bdb301e9fe04655d1129e9f9acad8254f68cc1846d`
- **Triage Result:** Matches `EuroAion_Game_dll_Pass590` baseline precisely.
- **PE Sections:** 11 sections. Code section `.aion1` contains virtualized VM dispatch.
- **Crypto Signal:** Static patterns (such as standard Aion XOR `staticKey` or public 4.6 keys `0xFE683CB9` / `0x73E79463`) are **not present** in the file-backed bytes of EuroAion's `game.dll`.

### 2. Supporting DLLs (`libeay32.dll`, `ssleay32.dll`, `version.dll`)
- **Path:** `inbox/euroaion/Aion/EuroAion/`
- **Triage Result:** Checked for custom hooks, modifications, and imports. All files return standard cryptographic routines or mouse/IP-redirection wrapper characteristics. None contain EuroAion-specific packet decryption transforms.

### 3. Baseline Controls (`Aion4.9`, `Gamez`)
- **Path:** `inbox/euroaion/Aion/Gamez/game.dll`
- **Crypto Signal:** Positive match for the standard public reference XOR `staticKey` (`nKO/WctQ0...`) and key constants (`0xCD92E4DF`, `0x3FF2CCCF`). Used as verification controls to confirm triage scanner function.

## Verification & Key Findings
- **Decoder Status:** 180 attempts against corrected Pass574 oracle frames using public reference variations return 0 matches.
- **XREF Status:** All virtualized call locations are protected. No file-backed routines expose the modified 7785 transform structure or modified key matrices.

## Decision Summary
- **Decision:** `blocked_static_binary_exhausted`
- **Reason:** The protected/virtualized EuroAion code is not recoverable from the static, file-backed bytes under the allowed offline/static rules.
