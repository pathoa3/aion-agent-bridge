# Pass602 Acquisition Report

## Scope & Objective
This report documents the Pass602 acquisition search for new code-side evidence regarding Aion 4.6/4.7.5 packet transforms, key schedules, or unpacked binaries (`Game.dll` or `aion.bin`). All operations were conducted statically and offline under strict safety constraints (no debugging of live clients, no anti-cheat bypasses, and no execution of unknown files).

## Search Strategy & Traced Repositories
We targeted several prominent community codebases and tools associated with Aion 4.6 and private server development:

1. **Aion-unique / AE_PacketSamurai (`NewCrypt.java`)**
   - **Details:** Checked the canonical Java-side packet cryptography tool `NewCrypt.java` from the `Aion-unique` repository (`tools/AE_PacketSamurai/src/com/aionemu/packetsamurai/crypt/NewCrypt.java`).
   - **Analysis:** Extracted the core functions:
     - `checksum(byte[] raw)`: An XOR-based validation loop over 4-byte boundaries.
     - `encXORPass(byte[] raw, int key)`: A rolling XOR cipher loop starting from offset 4 (after the size/header) that dynamically updates the XOR key with raw payload data and writes the final key to the last 4 bytes of the packet.
     - `decrypt` (via `BlowfishEngine`): Integrates standard Blowfish block cipher routines.
   - **Conclusion:** These routines represent the standard public `AionEmu`/`RageZone` reference cryptography already tested and exhausted in prior passes. They do not match the customized/hidden transform used in the EuroAion channel.

2. **beyond-aion / zzsort (`aion-version-dll`)**
   - **Details:** Examined the C++ implementation of the custom `version.dll` patch commonly used in Aion 4.6 private servers (e.g., EuroAion, Beyond Aion) to resolve Windows mouse bugs, camera glitches, and IP connection restrictions.
   - **Analysis:** The tool operates via DLL proxying (placed in `bin32`/`bin64`) and uses **MS Detours** to hook Winsock initialization, hostname resolution (`getaddrinfo`), or socket connections (`connect`). This allows the client to bypass the authorization server IP check.
   - **Conclusion:** It acts strictly as a network connection redirector and graphics/OS compatibility patch. It does not hook packet encryption/decryption routines (`send`, `recv`, `WSASend`, `WSARecv`) or contain code-side evidence of the game-channel packet transform.

3. **ActiveAntiCheat (AAC) / active64.sys**
   - **Details:** Traced references to the ActiveAntiCheat driver (`active64.sys` / `active32.sys`) used by EuroAion to isolate client processes.
   - **Analysis:** The driver runs at kernel-level to monitor memory, block debugger attachments, detect virtual machines, and prevent code injection or file modification. 
   - **Conclusion:** No public source dumps or unprotected handlers are available on public repositories.

## Decision Summary
- **Decision:** `no_artifact_obtained`
- **Reason:** `acquisition still blocked`
- **Next Steps:** No new, unpacked/unprotected EuroAion client binaries or customized transform specifications were discovered. The search path remains blocked for direct passive decoding until a genuinely unpacked version of EuroAion's `Game.dll`/`aion.bin` becomes available or further documentation/leak of the custom game-channel packet transform is obtained.
