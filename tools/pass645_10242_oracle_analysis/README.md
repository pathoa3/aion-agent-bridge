# Pass645 10242 Oracle Analysis

This pass treats `inbox/captures/s2c_oracle_world_entry.pcapng` as a 10242 chat-sidechannel capture. The capture has no 7785 flow, so these tools avoid forcing old world-flow or KXSEQ assumptions onto it.

Outputs are safe metadata only:

- `artifacts/pass645_10242_flow_inventory.csv`
- `artifacts/pass645_10242_packet_timeline.csv`
- `artifacts/pass645_10242_literal_text_hits.csv`
- `artifacts/pass645_10242_marker_correlation.csv`
- `artifacts/pass645_10242_oracle_decision.json`
- `artifacts/pass645_10242_oracle_summary.md`
- `inbox/codex_report.md`

The literal scanner may inspect packet payload bytes in memory, but it does not write payload bytes, payload hex, packet hashes, decoded blobs, keys, binaries, DLLs, EXEs, or secrets.

Run:

```powershell
powershell -ExecutionPolicy Bypass -File tools\pass645_10242_oracle_analysis\run_10242_oracle_analysis.ps1
```
