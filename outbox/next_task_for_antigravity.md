# Next task for Antigravity — Pass603 targeted acquisition

Continue from Pass602. Do not repeat broad source-code searches already completed.

Current clean state:
- Pass599 fixed PCAP extraction.
- Pass600 corrected decoder test failed public/reference crypto.
- Pass601 source candidates archived; one aion-proxy variant tested and failed.
- Pass602 acquisition found no artifact.
- Current blocker: no unpacked/less-protected client binary or non-public EuroAion transform/key evidence.

Task:
Find concrete downloadable candidate artifacts only.

Accepted targets:
1. Aion 4.6 / 4.7.5 client archive containing Game.dll or aion.bin.
2. Unpacked / less-protected Game.dll or aion.bin.
3. Forum attachment or mirror that contains actual client binaries.
4. Decompiled/static source with a non-public game-channel packet transform/key schedule.

Reject:
- AionEmu/RageZone/NewCrypt/Crypt public reference crypto.
- zzsort/version.dll redirector-only code.
- Cheat Engine scripts.
- bot offsets.
- memory hacks.
- injection/debugging/anti-cheat bypass instructions.
- packet injection tools.

Required output:
- inbox/antigravity_report.md
- artifacts/pass603_candidates.md
- artifacts/pass603_candidates.csv
- artifacts/pass603_decision.json

For each candidate:
- URL/source
- file name/version if visible
- artifact type
- downloadable yes/no
- why it may expose packet crypto
- duplicate/public-reference risk
- classification:
  useful_candidate / weak_candidate / duplicate_reference / unsafe_reject / unavailable

Decision:
If no concrete downloadable artifact is found:
  decision = no_artifact_obtained
  next = stop_repeating_same_search

If a candidate artifact is found:
  decision = candidate_artifact_found
  next = manual_download_to_local_new_samples

Hard rules:
No running unknown binaries. No live process. No debugger. No memory dump. No injection. No anti-cheat bypass. No packet injection. Do not commit binaries, PCAPs, archives, API keys, or private files to GitHub.