# Pass605 Custom Transform Acquisition Report

## Scope & Objective
This report details the targeted web and community source search for public code leaks, decompiled handlers, or exact constant descriptions of the custom packet transform used on EuroAion (Aion 4.6). The search focused strictly on source-level material matching the custom protocol variations while rejecting public reference clones.

## Target Definitions
- **Custom 7785 Cipher / Key Schedules:** Searched for modified `KeyXor`, `KeyAdd`, `OpXor`, and `OpAdd` constants, especially C++/C# hooks targeting 4.6 client revisions.
- **Decompiled Crypt Functions:** Checked for non-standard packet structures matching the `[Size] [Opcode] [~Opcode Checksum]` verification blocks but implementing custom encryption layouts.

## Scanned Sources & Results
1. **GitHub Repositories (`Aion-unique` & Emulator Forks)**
   - **Details:** Inspected class definitions for `com.aionemu.packetsamurai.crypt.NewCrypt`.
   - **Analysis:** The standard code-base implements rolling XOR based on the canonical `staticKey` (`nKO/WctQ...`) and default constants (`0xCD92E4DF`, `0x3FF2CCCF`). No alternative custom transform modules matching the EuroAion game-channel signatures are present in the public tree.
   
2. **Community Reverse Engineering Forums (ElitePvPers / RageZone)**
   - **Details:** Searched for custom key updates and packet decryption strategies matching Aion 4.6.
   - **Analysis:** Developers discuss the generic structure of Blowfish + XOR keys (`opXor`, `opAdd`, `keyXor`, `keyAdd`). However, no specific key configurations or functional code changes corresponding to the EuroAion client version have been leaked or publicly cataloged. Operators handle these as proprietary overrides within local configurations.

## Decision Summary
- **Decision:** `no_artifact_obtained`
- **Reason:** `acquisition still blocked` (no public source leak, decompiled binary handler, or documentation exists for the custom EuroAion packet transform). The search path for static key configurations remains blocked.
