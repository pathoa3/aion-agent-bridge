# Pass603 Acquisition Candidates

## Scope
- Continued from Pass602; targeted acquisition only. Did not repeat broad Pass602 source-code searches.
- Target: Find concrete downloadable candidate artifacts (unpacked Game.dll/aion.bin, Aion 4.6/4.7.5 client archives, forum attachments or mirrors containing actual client binaries, decompiled/static source showing non-public game-channel packet transforms).
- Rejected AionEmu/RageZone/NewCrypt/Crypt public reference crypto, zzsort/version.dll redirector-only code, Cheat Engine scripts, bot offsets, memory hacks, injection/debugging/anti-cheat bypass instructions, and packet injection tools.

## Decision
- decision: `no_artifact_obtained`
- reason: `stop_repeating_same_search` (the targeted search confirms no concrete unpacked/less-protected 4.6 client binaries or non-public custom packet transform codebases are publicly downloadable; remaining files are public reference duplicates or connection wrappers).

## Candidates

### 1. EuroAion 4.6 Client (Official Torrent)
- **URL/Source:** https://euroaion.com/en-US/Home/Download
- **Exact File Name/Version:** `EuroAion_Client.torrent`
- **Artifact Type:** archive/torrent
- **Downloadable:** yes
- **Probably Duplicate/Public Reference:** no
- **Why it might expose packet crypto:** The target client binaries (Themida-protected `game.dll` and `aion.bin`) are in the torrent, but do not provide unpacked/unprotected code.
- **Safety/Risk Note:** Safe to download for offline analysis only; do not execute the binaries to avoid security/malware risks.
- **Classification:** weak_candidate

### 2. Aion Nova 4.6 Client (Official Installer)
- **URL/Source:** https://aion-nova.com/
- **Exact File Name/Version:** Aion Nova client installer
- **Artifact Type:** archive
- **Downloadable:** yes
- **Probably Duplicate/Public Reference:** no
- **Why it might expose packet crypto:** Standard 4.6 client base used for private server connection, but likely contains the same Themida packing on core binaries.
- **Safety/Risk Note:** Safe for offline analysis only; do not run.
- **Classification:** weak_candidate

### 3. GoldAion 4.6 Client
- **URL/Source:** https://goldaion.com/
- **Exact File Name/Version:** GoldAion client files
- **Artifact Type:** archive
- **Downloadable:** yes
- **Probably Duplicate/Public Reference:** no
- **Why it might expose packet crypto:** Alternative server 4.6 client, but protected by active client-side shields/packers.
- **Safety/Risk Note:** Safe for offline analysis only; do not run.
- **Classification:** weak_candidate

### 4. Unpacked Aion 4.6 Client Binaries
- **URL/Source:** None (Public mirror search gap)
- **Exact File Name/Version:** `game.dll` / `aion.bin` (Unpacked)
- **Artifact Type:** binary
- **Downloadable:** no
- **Probably Duplicate/Public Reference:** no
- **Why it might expose packet crypto:** Provides clean code paths to reconstruct packet transformation layout.
- **Safety/Risk Note:** Safe for static review.
- **Classification:** unavailable

### 5. Custom 4.6 Packet Transform Specification / Source Leak
- **URL/Source:** None (Public search gap)
- **Exact File Name/Version:** Decompiled/static custom transform source
- **Artifact Type:** source
- **Downloadable:** no
- **Probably Duplicate/Public Reference:** no
- **Why it might expose packet crypto:** Would contain modified XOR constants or custom rolling logic.
- **Safety/Risk Note:** Safe for static review.
- **Classification:** unavailable
