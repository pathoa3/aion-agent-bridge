# Next task for Antigravity

Pass603 targeted acquisition only. Do not repeat broad Pass602 source-code searches.

Find concrete downloadable candidate artifacts only:
1. Aion 4.6 / 4.7.5 client archive containing Game.dll or aion.bin.
2. Unpacked / less-protected Game.dll or aion.bin.
3. Forum attachment or mirror that contains actual client binaries.
4. Decompiled/static source with a non-public game-channel packet transform/key schedule.

Reject AionEmu/RageZone/NewCrypt/Crypt public reference crypto, zzsort/version.dll redirector-only code, Cheat Engine scripts, bot offsets, memory hacks, injection/debugging/anti-cheat bypass instructions, and packet injection tools.

Write:
- inbox/antigravity_report.md
- artifacts/pass603_candidates.md
- artifacts/pass603_candidates.csv
- artifacts/pass603_decision.json

If no concrete downloadable artifact is found:
decision = no_artifact_obtained
next = stop_repeating_same_search

If a candidate artifact is found:
decision = candidate_artifact_found
next = manual_download_to_local_new_samples

Do not commit binaries, PCAPs, archives, API keys, or private files to GitHub.
