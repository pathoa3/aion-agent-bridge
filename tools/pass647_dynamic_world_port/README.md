# Pass647 Dynamic World Port Analysis

Detects the actual EuroAion world/game TCP flow dynamically instead of assuming port 7785.

For the fresh broad capture, expected candidates are:

- `7780`: world/game candidate when long-lived and high-volume against `51.83.147.97`.
- `10242`: visible-chat sidechannel candidate.
- `2106`: login candidate.
- `11000`: launcher/update/server-list style candidate.

Scripts inspect the local pcap only to compute safe metadata and literal-match counts. They do not write packet payloads, ciphertext, plaintext blobs, packet hashes, binaries, DLLs, EXEs, keys, tokens, or secrets.
