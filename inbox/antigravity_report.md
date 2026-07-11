# Antigravity Parallel Evidence Audit Report - Pass607 Lobby Seed Followup

## 1. Lobby SM_KEY & Seed Verification
- **Verified Packet:** `Pkt # 7522` in `startup_login_world_entry.pcapng` has raw ciphertext `c1 66 83 f7 d5 26 5d b9 3c 68 fe`.
- **Decryption:** Decodes using the standard `Aion75Mask` (`CA 66 7A F6 83 20 A3`) to yield the protocol header `0B 00 F9 01 56 06 FE`.
- **Extracted Seed:** The seed is unambiguously extracted as **`73 5A 12 08`**.

## 2. Chat Packet Timing & Alignment
- **Pre-Rekey Status:** All target chat packets (8745, 8844, and 8974) occur at approximately `17:03`, which is **definitely before** the world-entry/re-key event `Pkt # 9741` at `17:04:45`.
- **Length Alignment:**
  - `Pkt # 8745` (36 bytes) matches `KXBOOT_SAY_01` (26 bytes text + 10 protocol bytes).
  - `Pkt # 8844` (70 bytes) matches `KXBOOT_SAY_02_AAAAAAAAAAAAAAAA` (58 bytes text + 10 protocol bytes + 2 padding bytes).
  - `Pkt # 8974` (58 bytes) matches `KXBOOT_SAY_03_1234567890` (46 bytes text + 10 protocol bytes + 2 padding bytes).

## 3. Codex Lobby Run Status
- **Status:** Codex has not yet executed the lobby seed trials.
- **Previous Trial Review:** In its previous run, Codex tested only the world seed `39 90 C5 A2` on packets after packet 9741.
- **Venv Availability:** Verified that Python `cryptography` is available in `C:\AionTools\aion_decoder_agent\.venv`.

## 4. Next Bounded Hypotheses
If the lobby seed test does not yield cleartext directly, we have outlined next-step bounded hypotheses under `artifacts/pass607_antigravity_next_hypotheses.md`, including:
- Key state mutations from C2S packets between 7522 and 8745.
- C2S and S2C key state divergence.
- Offset alignments for Blowfish decryption.
- Custom XORpass LCG multipliers or addends.
