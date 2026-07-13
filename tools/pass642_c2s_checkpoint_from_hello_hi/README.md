# Pass642 C2S Checkpoint From Known Text

Derives a local-only C2S packet-key checkpoint from a known plaintext packet in the old `Hello Hi` capture.

Usage:

```powershell
python tools\pass642_c2s_checkpoint_from_hello_hi\derive_c2s_key_from_known_text.py --capture-dir C:\AionTools\captures\aion_capture_20260704_011724 --known-text "Hello Hi" --candidate-frame 370 --direction C2S --derive-checkpoint-only
```

The scripts write safe metadata only:
- no raw packet payloads
- no ciphertext
- no decoded byte blobs
- no packet hashes
- no derived key bytes
- no binaries or secrets

This is C2S-only anchoring. S2C initial key derivation remains unsolved.
