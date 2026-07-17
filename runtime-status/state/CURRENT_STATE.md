# EuroAion decoder current state

Repository: `https://github.com/pathoa3/aion-agent-bridge.git`
Main head: `3c635c7ba12de475fb95d50c6417512add28d8ea`
Updated (Unix): `1784319734`

| Worker | Alive | Status age | Reason | Instructions | APIs | RIP | Output estimate | Projected instruction | Game mapped | Targets | Reconstructed |
|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|
| AION_LOCAL_WORKER_V22 | False | 90699.26809430122 | process_not_running | 1471000000 | 964 | `0x18021f34e` |  |  | False | 0/0 | False |
| AION_LOCAL_WORKER_V22_2 | True | 311.14124727249146 | running | 7210006268 | 964 | `0x18021f374` |  |  | False | 0/3 | False |

## Acceptance targets

- `0x10328DE0`: receive loop
- `0x103294B0`: normal Aion receive transform
- `0x1120AE70`: provider global
- Provider object → vtable → slot `+0x18` must resolve coherently
- Final network validation: 17/17 oracle messages

Large binaries, packet captures, DLLs, memory images, ZIPs, raw API buffers and absolute local paths are not committed.
