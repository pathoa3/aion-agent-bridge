# Pass643 Evening Capture Operator Runbook

1. Start capture before login/world entry:

```powershell
cd C:\AionTools\aion-agent-bridge
powershell -ExecutionPolicy Bypass -File tools\pass643_evening_capture_operator\start_s2c_oracle_capture.ps1
```

2. Login and enter world on the target client.

3. Have another character/account/friend send these visible messages to the target:

```text
S2C_ORACLE_001_A1B2
S2C_ORACLE_002_C3D4
S2C_ORACLE_003_0123456789
S2C_ORACLE_004_REPEAT
S2C_ORACLE_004_REPEAT
```

Prefer `/whisper`; otherwise use nearby `/say`. The target client must visibly receive the text from the server.

4. Immediately after each marker appears, log it:

```powershell
powershell -ExecutionPolicy Bypass -File tools\pass643_evening_capture_operator\log_s2c_marker.ps1 -Text "S2C_ORACLE_001_A1B2"
```

5. Stop capture:

```powershell
powershell -ExecutionPolicy Bypass -File tools\pass643_evening_capture_operator\stop_s2c_oracle_capture.ps1
```

6. Run safe post-capture analysis:

```powershell
powershell -ExecutionPolicy Bypass -File tools\pass643_evening_capture_operator\run_after_capture_full.ps1
```

Never commit PCAPs, packet payloads, ciphertext, plaintext blobs, packet hashes, binaries, DLLs, EXEs, keys, tokens, or secrets.
