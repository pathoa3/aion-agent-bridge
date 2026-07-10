# Pass604 Codex Static Grind Report

## Scope & Objective
This report details the static triage, signature matching, and PE evaluation conducted on the client files in `inbox/euroaion` to identify game-channel packet transform or key candidates for EuroAion (Aion 4.6).

## Triage Scans & Verification
1. **EuroAion `game.dll` and `aion.bin`**
   - **Triage Result:** Verified match against baseline `EuroAion_Game_dll_Pass590`. 
   - **PE Layout:** Contains 11 sections. Code section `.aion1` contains virtualized dispatcher blocks protecting import XREFs.
   - **Crypto Signatures:** Static signature checks for the classic Aion XOR `staticKey` (`nKO/WctQ...`) and standard constants (`0xCD92E4DF` etc.) return **negative** on the file-backed bytes of EuroAion `game.dll`.

2. **Control Baselines (`Aion4.9`, `Gamez`)**
   - **Triage Result:** Confirmed presence of the exact standard `staticKey` and key constants in the `Gamez` client, validating the static scanner tool parameters.

## Summary & Next Steps
- **Decision:** `blocked_static_binary_exhausted`
- **Reason:** The virtualized EuroAion binary core hides the custom 7785 decryption scheduling routines, rendering them unrecoverable from direct static file-backed bytes under the restricted offline analysis rules. No new key matrices or function offsets were exposed.
