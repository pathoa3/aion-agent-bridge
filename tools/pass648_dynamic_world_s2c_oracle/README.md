# Pass648 Dynamic World 7780 S2C Oracle

Runs a bounded S2C crib/keyroll attempt against the dynamically detected world flow from Pass647.

Inputs are the local broad pcap and safe Pass647 metadata. The scripts inspect packet payloads locally to derive candidate metadata, but they never write raw payloads, ciphertext, plaintext blobs, packet hashes, derived key bytes, binaries, DLLs, EXEs, keys, tokens, or secrets.

Decoder success is only allowed when exact known marker plaintext is independently recovered. Crib-derived slot consistency alone is reported as a hypothesis, not success.
