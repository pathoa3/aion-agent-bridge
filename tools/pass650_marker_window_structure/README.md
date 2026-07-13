# Pass650 Marker Window Structure

Analyzes full packet windows around current `S2C_A_` length-ladder markers instead of relying on only the nearest packet.

Outputs are safe metadata: timing, direction, packet length, sequence similarity, and aggregate length-signal summaries. No packet payload bytes, ciphertext, plaintext blobs, packet hashes, keys, binaries, DLLs, EXEs, tokens, or secrets are written.
