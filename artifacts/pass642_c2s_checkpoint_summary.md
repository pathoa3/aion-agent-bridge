# Pass642 C2S Checkpoint Summary

Input capture: `C:\AionTools\captures\aion_capture_20260704_011724`

Results:
- Frame 370 found: True
- Frame 370 C2S len 26: True
- UTF-16LE `Hello Hi` length model matches: True
- UTF-16LE conflict-free packet key slots derived: 0
- Full packet key accepted locally only: False
- Exact UTF-16LE frame 370 text recovered locally: False
- Opcode plausible on exact UTF-16LE candidate: False
- C2S forward roll validated: False
- C2S backward roll validated: False
- Meaningful nearby C2S packet labels: 0
- S2C plaintext recovered: false

ASCII `Hello Hi` was tested only as a negative/control and was not accepted as checkpoint evidence. No key bytes, packet hex, ciphertext, decoded blobs, packet hashes, binaries, or secrets were written to committed artifacts.

Interpretation: frame 370 remains a strong length/alignment marker for the user-provided action, but the requested UTF-16LE packet-key checkpoint was not validated from this old capture. The next useful path is still the longer repeated S2C oracle from Pass638.
