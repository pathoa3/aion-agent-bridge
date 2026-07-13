# Pass637 S2C Oracle Capture Kit

Use this kit for the next S2C known-plaintext capture.

Paths:
- PCAP: `C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng`
- Log: `C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt`

Workflow:
1. Copy or fill `s2c_known_plaintext_log_template.txt` at the log path above.
2. Run `start_s2c_oracle_capture.ps1` before world entry.
3. Enter world.
4. Have a second character/friend send these exact visible markers immediately:
   - `S2C_ORACLE_001_A1B2`
   - `S2C_ORACLE_002_C3D4`
   - `S2C_ORACLE_003_0123456789`
   - `S2C_ORACLE_004_REPEAT`
   - `S2C_ORACLE_004_REPEAT`
5. Record exact visible local time and text in the log.
6. Run `stop_s2c_oracle_capture.ps1` after all markers are visible.
7. Run `validate_capture_presence.py` to produce a Git-safe status CSV.

Do not commit the PCAP or any raw packet bytes. Commit only metadata/status artifacts.
