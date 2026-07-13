# Pass641 Hello Hi Oracle Tools

Targeted, offline-only tools for the old `aion_capture_20260704_011724` capture.

Usage:

```powershell
python tools\pass641_hello_hi_oracle\audit_hello_hi_capture.py --capture-dir C:\AionTools\captures\aion_capture_20260704_011724 --known-text "Hello Hi" --candidate-frame 370
```

The tools write safe metadata artifacts only. They do not write packet hex, raw payloads, ciphertext, plaintext blobs, packet hashes, binaries, keys, or secrets.

Scope:
- Build a focused frame 340-390 timeline from `records_7785_old.tsv`.
- Validate frame 370 as a C2S `Hello Hi` candidate by length and bounded crib-slot consistency.
- Test only nearby S2C records within +/-20 records as crib candidates.
- Scan 10242 stream files for literal known strings without committing raw stream bytes.

No live process, debugger, memory dump, injection, or packet injection is used.
