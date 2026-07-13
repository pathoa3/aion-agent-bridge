# Pass636 Next Capture Plan

Current capture result:
- KXSEQ echo crib candidates: `0`
- MOTD/phase-5 candidates: `2705`
- validated S2C plaintext candidates: `0`

The existing capture is insufficient because KXSEQ chat text does not appear as a detectable S2C echo in the tested windows, and MOTD/phase-5 cribs produce many partial slot candidates without a validated full-packet key or keyroll.

Next capture should provide a stronger S2C oracle while keeping all analysis offline:

1. Capture a fresh startup/world-entry session with a unique server-visible event that is known to produce S2C text, preferably a system notification or self-visible chat echo with an uncommon marker.
2. Record exact wall-clock time, Wireshark frame number if visible, direction, and the exact UTF-16LE plaintext marker.
3. Use at least 16 ASCII characters with mixed letters/digits, for example a marker shaped like `KXS2C_YYYYMMDD_NNNN`, so the UTF-16LE crib spans all 8 key slots with redundancy.
4. Include two repeated S2C-visible messages separated by a few seconds to validate keyroll continuity.
5. Export only the PCAP locally; do not commit raw packets, payload hex, packet hashes, or decoded blobs.

If a server-visible S2C text oracle cannot be produced, the next static artifact needed is a receive-side key derivation export that resolves the S2C initial key before packet decrypt.
