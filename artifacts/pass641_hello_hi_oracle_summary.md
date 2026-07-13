# Pass641 Hello Hi Old Capture Oracle Summary

Capture directory found: `C:\AionTools\captures\aion_capture_20260704_011724`.

Key findings:
- `aion_capture.pcapng` found: True
- `records_7785_old.tsv` found: True
- Frame 370 present as C2S len 26: True
- Expected `Hello Hi` C2S length is UTF-16LE 16 bytes + 10 = 26; frame 370 matches that length: True
- Exact C2S plaintext recovered: false
- Nearby S2C candidates tested: 24
- Exact S2C plaintext recovered: false
- 10242 literal `Hello Hi` found: False

Interpretation: frame 370 is useful as a weak alignment marker and likely C2S `Hello Hi` candidate by unique length, but it does not unlock S2C by itself. The old capture does not provide validated S2C plaintext or S2C keyroll evidence.

Next action: use the Pass638 fresh capture plan with longer repeated S2C-visible markers.
