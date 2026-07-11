# Pass608 Antigravity KXSEQ Capture Audit

We performed a capture quality audit on the new `startup_world_open_kxseq.pcapng` capture file:

## 1. Audit Findings
- **Main 7785 Flow:** `192.168.178.127:58361 <-> 54.37.197.248:7785`.
- **SM_KEY Presence:** Yes, `SM_KEY` appears before the first known chat message.
- **Dual SM_KEY Handoffs:**
  - `Frame # 4094` (Lobby SM_KEY): Decodes via `Aion75Mask` to seed `19 1A 76 23`.
  - `Frame # 4119` (World/Re-key SM_KEY): Decodes via mask `8E 37 81 4B E3 F5 43` to seed `2D 66 BD 65`.
- **Intermediate C2S Packets:** There are **15 intermediate C2S data packets** between the last relevant SM_KEY (`Frame # 4119`) and the first chat packet `KXSEQ_001` (`Frame # 4329`).
- **Length Alignment:** All target packet lengths match the `UTF-16LE + 10` protocol model exactly, with zero block-size padding observed.
- **Repeated Messages:** The two consecutive identical messages (`KXSEQ_010_REPEAT` at Frame 4429 and Frame 4435) have the exact same length (42 bytes) but completely different encrypted payloads, confirming continuous state mutation.
- **Capture Quality:** This capture is significantly cleaner than the old one, reducing the intermediate packet count from 31 to 15 (a 51.6% reduction).
