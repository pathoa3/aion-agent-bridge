# Aion Agent Bridge

Public coordination board for the EuroAion 7785 decoder project.

This repository is for **reports, prompts, decisions, candidate links, and sanitized summaries only**.

Do **not** commit:

- `.pcap` / `.pcapng` captures
- game binaries such as `.dll`, `.bin`, `.exe`
- archives containing private samples
- API keys, tokens, cookies, credentials, `.env`
- live-memory dumps, debugger output, injection tooling, anti-cheat bypass material

Private artifacts stay local under:

```text
C:\AionTools\aion_decoder_agent\
```

## Current objective

Find new code-side evidence for the EuroAion/Aion 4.6 game-channel packet transform/key schedule so the Pass574 sample capture can eventually be converted to validated clear text.

Current clean state:

- Pass599 fixed PCAP extraction.
- Pass600 retested corrected raw payloads and public/reference crypto failed.
- Pass601 checked source candidates; one aion-proxy variant was tested and failed.
- Decoder success: no.
- Current blocker: missing EuroAion/comparable transform/key evidence.

Use `AGENT_PROTOCOL.md` before writing reports or tasks.
