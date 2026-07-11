# Pass607 Antigravity Startup Timing Audit

## 1. Audit Overview
We conducted a chronological and logical audit of packet timestamps and sequence numbers in `startup_login_world_entry.pcapng` to map the exact timing of typed messages against connection and key-exchange events.

## 2. Key Findings & Timeline
- **KSTART_001 Exists:** No, `KSTART_001` does not exist in `known_plaintext_log.txt`.
- **First Handoff (Lobby Session):** `Pkt # 7522` at `17:01:52.960992` local time. The server sends `SM_KEY` encrypted with `Aion75Mask` (`CA 66 7A F6 83 20 A3`), yielding the decoded seed **`73 5A 12 08`**.
- **Chat Messages (Lobby Session Phase):** 
  - `Index 8745` (Len: 36) at `17:03:02` (`KXBOOT_SAY_01`).
  - `Index 8844` (Len: 70) at `17:03:11` (`KXBOOT_SAY_02_AAAAAAAAAAAAAAAA`).
  - `Index 8974` (Len: 58) at `17:03:21` (`KXBOOT_SAY_03_1234567890`).
  All three chat messages were sent in this phase and are encrypted under the lobby session key state initialized by seed **`73 5A 12 08`**.
- **Second Handoff (World Handoff/Re-Key):** `Pkt # 9741` at `17:04:45.197172` local time. The server sends a second `SM_KEY` encrypted with the custom mask `F9 7B 38 61 99 F4 5A`, yielding seed **`39 90 C5 A2`**.
- **TCP Sequence Continuity:** TCP sequence numbers are contiguous throughout both phases, proving it is a single, uninterrupted TCP connection with a mid-session re-key.
- **Timing Alignment:** The `Chat.log` timing (reported approx 17:03) aligns perfectly with packets 8745 to 8974.

## 3. Recommended Packet Range for Codex
Codex must prioritize testing the seed **`73 5A 12 08`** (BE/LE) on packets in the range **8745 to 8974** where the target chat messages actually reside.
