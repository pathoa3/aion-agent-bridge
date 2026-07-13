# Pass638 Capture Readiness Summary

Pass638 prepared the repo for the next fresh S2C oracle capture without rerunning broad static work or old-capture brute force.

Completed:
- Reviewed and patched `tools/agent_helpers/agent_safe_checkpoint.ps1` so it prints the push exit code, exits non-zero on push failure, rejects the required forbidden patterns, and avoids staging unrelated old workspace leftovers by default.
- Created `tools/pass638_after_capture/run_s2c_oracle_after_capture.ps1` with `-PcapPath`, `-KnownLogPath`, `-OutDir`, and `-DryRun` support.
- Created `tools/pass638_after_capture/validate_known_plaintext_log.py` for safe schema/marker validation.
- Created `tools/pass638_after_capture/extract_s2c_window_metadata.py` for safe frame/direction/length/timing metadata extraction only.
- Built `artifacts/pass638_capture_tool_manifest.csv` from the actual local tool paths. `tools/pass637_s2c_capture_prep` is not present in latest main.
- Wrote the evening runbook with the exact `tcp port 7785` capture filter and S2C oracle markers.
- Executed dry-run mode; it did not process packet payloads. The future PCAP/log are not present yet, and all required tool paths exist.

Readiness: ready for tonight's fresh capture. The next unlock remains a fresh S2C-visible oracle PCAP plus matching known plaintext log.
