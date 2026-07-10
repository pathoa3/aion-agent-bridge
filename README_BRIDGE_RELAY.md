# Aion Agent Bridge Relay v1

Local relay for two-way communication through `pathoa3/aion-agent-bridge`.

Purpose:
- Agents write reports to the public GitHub bridge.
- The relay reads reports and local state.
- The relay calls OpenAI API supervisor if configured.
- The relay writes supervisor decisions/tasks back to GitHub.

Do not commit PCAPs, binaries, API keys, tokens, credentials, or private local captures.

## Setup

```bat
cd C:\AionTools
git clone https://github.com/pathoa3/aion-agent-bridge.git
cd C:\AionTools\aion-agent-bridge
```

Copy this package content into the repo root.

Create `.env` locally from `.env.example` and do NOT commit it.

```bat
pip install -r requirements_bridge.txt
python tools\bridge_relay.py --init
python tools\bridge_relay.py --once
```

## Modes

- `--init`: create/refresh safe bridge files locally.
- `--once`: read inbox/state, create supervisor decision/task files.
- `--push`: after `--once`, commit and push through local git.
- `--loop`: repeat every BRIDGE_POLL_SECONDS.

Example:

```bat
python tools\bridge_relay.py --once --push
```
