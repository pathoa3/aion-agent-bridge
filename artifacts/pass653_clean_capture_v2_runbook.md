# Pass653 Clean Capture v2 Runbook

This kit is prepared only; it does not start capture automatically.

1. Run `tools\pass653_10242_labeler_hardening\clean_capture_v2_start.ps1` to archive the mixed known log and create a fresh header.
2. Start packet capture manually with:
   `host 51.83.147.97 and (tcp port 2106 or tcp port 11000 or tcp port 10242 or tcp portrange 7770-7799)`
3. Run `tools\pass653_10242_labeler_hardening\clean_capture_v2_marker_commands.ps1` and send the printed whisper-only markers.
4. Send five 64-character markers 20-30 seconds apart, then five 96-character markers 20-30 seconds apart.
5. Stop capture manually.
6. Run `tools\pass653_10242_labeler_hardening\clean_capture_v2_stop_and_analyze.ps1`.

Dynamic world-port detection remains enabled through the existing pipeline helpers. Do not add group markers in the first clean pass.
