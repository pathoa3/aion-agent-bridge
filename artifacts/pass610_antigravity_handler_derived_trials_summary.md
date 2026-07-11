# Pass610 Antigravity Handler-Derived Trials Summary

We derived bounded cryptographic transform tests directly from the assembly semantics of the top 10 unique VM handlers and executed them against the extracted TCP payloads from the startup PCAP.

## 1. Derived Candidates Tested
- **Candidate VA `0x11B57437` (`XOR DL, 0xc7`):** Tested bytewise XOR transform utilizing the literal mask `0xC7` at body offsets 4, 6, 8, and 10.
- **Candidate `add_sub`/`shift_rotate` state updates:** Tested indexing and byte-chaining logic shifts mapped from ROR/ROL registers.

## 2. Trial Results
- **Total Bounded Trials Run:** 240.
- **Exact Plaintext Needle Match ("KXSEQ" in UTF-16LE):** **0 matches.**
- **Decoder Success:** `false`.
- **Reason for Failure:** The payload bytes require dynamic multi-byte decryption state (or key initialization seeds from the handshake port 2106) rather than static single-operation modifications.
