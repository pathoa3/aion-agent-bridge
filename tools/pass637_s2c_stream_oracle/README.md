# Pass637 S2C Stream Oracle Tools

This folder contains offline-only tools for searching the reassembled TCP byte stream from the existing Pass636 KXSEQ capture.

Tools:
- `tcp_reassemble_7785.py`: strict TCP sequence reassembly for `192.168.178.127:58361 <-> 54.37.197.248:7785`; writes stream range metadata only.
- `validate_c2s_stream_alignment.py`: verifies known solved C2S KXSEQ frames map into the C2S stream and match the UTF-16LE+10 length model.
- `s2c_stream_crib_drag.py`: scans the continuous S2C stream for KXSEQ and MOTD cribs; writes offset/label/slot metadata only.
- `s2c_deframe_hypotheses.py`: tests safe S2C packet-boundary hypotheses around known small S2C frames.

No tool writes raw stream bytes, packet payload bytes, packet hashes, derived key bytes, or decrypted blobs.
