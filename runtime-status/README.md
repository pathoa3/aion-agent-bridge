# Aion runtime status

This folder is maintained automatically on the `worker/runtime-status` branch.
It contains compact, privacy-safe state and reproducibility metadata for the
EuroAion 4.6 offline chat-decoder work.

Committed here:

- compact worker and sidecar status JSON;
- milestone/progress-only worker-log lines;
- API names and return values without raw argument buffers;
- artifact names, sizes, and SHA-256 hashes;
- tracked-file inventory and recent commit paths from `main`;
- acceptance targets and current progress.

Never committed here:

- game, Aegis, EuroAion, or other binaries;
- reconstructed memory images;
- packet captures;
- ZIP/7z archives;
- raw API argument buffers;
- absolute local filesystem paths;
- credentials or tokens.

Acceptance targets:

- `0x10328DE0` — receive loop;
- `0x103294B0` — normal Aion receive transform;
- `0x1120AE70` — provider global;
- provider object → vtable → slot `+0x18` resolves coherently;
- final network validation — exact 17/17 oracle messages.
