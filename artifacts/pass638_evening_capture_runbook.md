# Pass638 Evening S2C Oracle Capture Runbook

Goal: produce a fresh S2C-visible oracle capture for immediate offline validation. Do not run any debugger, injector, dump, patch, or bypass workflow.

1. Start Wireshark before world entry.
2. Use capture filter exactly:

```text
tcp port 7785
```

3. Enter world on the target client.
4. Use another character/account/friend to send messages visible to the target. Prefer `/whisper` if it is visible only on the target; otherwise use nearby `/say`.
5. Send these exact messages, in order:

```text
S2C_ORACLE_001_A1B2
S2C_ORACLE_002_C3D4
S2C_ORACLE_003_0123456789
S2C_ORACLE_004_REPEAT
S2C_ORACLE_004_REPEAT
```

6. Record exact local time and visible text in:

```text
C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt
```

The log must be CSV/TSV-like with columns:

```text
timestamp_local,frame_hint,direction,visible_text,notes
```

Use `S2C` in `direction` for every visible oracle marker.

7. Save the capture as:

```text
C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng
```

8. Run the post-capture pipeline from the repo:

```powershell
cd C:\AionTools\aion-agent-bridge
powershell -ExecutionPolicy Bypass -File tools\pass638_after_capture\run_s2c_oracle_after_capture.ps1
```

9. Checkpoint safe outputs only:

```powershell
powershell -ExecutionPolicy Bypass -File tools\agent_helpers\agent_safe_checkpoint.ps1 -Message "Analyze fresh S2C oracle capture"
```

Never commit the PCAP, raw packet bytes, ciphertext, plaintext blobs, packet hashes, binaries, keys, or secrets.
