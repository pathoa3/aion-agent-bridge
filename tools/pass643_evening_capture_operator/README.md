# Pass643 Evening S2C Capture Operator Kit

This kit is for one evening capture workflow. It does not run the game client, attach/debug/inject/hook/dump, or bypass protection.

## Step 1: Start capture

```powershell
cd C:\AionTools\aion-agent-bridge
powershell -ExecutionPolicy Bypass -File tools\pass643_evening_capture_operator\start_s2c_oracle_capture.ps1
```

If no interface is supplied, choose the active network interface from the list.

## Step 2: Login / enter world

Start capture before login/world entry, then enter world on the target client.

## Step 3: Receive visible S2C markers

Have another character/account/friend send these exact visible messages to the target character:

```text
S2C_ORACLE_001_A1B2
S2C_ORACLE_002_C3D4
S2C_ORACLE_003_0123456789
S2C_ORACLE_004_REPEAT
S2C_ORACLE_004_REPEAT
```

Prefer `/whisper` to target if it is visible on target. Otherwise use nearby `/say`.

The important point: the target client must visibly receive the text from the server.

## Step 4: Log each marker live

After each visible message, run for example:

```powershell
powershell -ExecutionPolicy Bypass -File tools\pass643_evening_capture_operator\log_s2c_marker.ps1 -Text "S2C_ORACLE_001_A1B2"
```

Repeat for every marker at the moment it appears.

## Step 5: Stop capture

```powershell
powershell -ExecutionPolicy Bypass -File tools\pass643_evening_capture_operator\stop_s2c_oracle_capture.ps1
```

## Step 6: Run analysis

```powershell
powershell -ExecutionPolicy Bypass -File tools\pass643_evening_capture_operator\run_after_capture_full.ps1
```

The post-capture pipeline writes safe metadata only. Do not commit PCAPs, packet payloads, ciphertext, plaintext blobs, packet hashes, binaries, keys, or secrets.
