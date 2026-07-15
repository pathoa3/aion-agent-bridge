# Pass665 Active Receive Hook / CrySystem Bootstrap

Offline-only static pass for the Pass665 delta prompt.

The runner parses local PE metadata for the mapped Game image, installed EuroAion modules, and the extracted handover inputs. It records import-slot baselines, CrySystem inventory, dynamic-resolution evidence, hook/write candidates, and AegInitEngine argument candidates without committing binaries, raw bytes, keys, packet data, or hashes of private packets.

Run:

```powershell
powershell -ExecutionPolicy Bypass -File tools\pass665_active_recv_hook\run_pass665_all.ps1
```
