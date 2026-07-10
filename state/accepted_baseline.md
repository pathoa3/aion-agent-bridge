# Accepted baseline

- Pass599 fixed PCAP extraction.
- Frame 7166 raw TCP payload length is 22.
- Correct C2S length model is UTF-16LE byte length + 10.
- Pass600 used corrected full raw TCP payloads.
- Public/reference decoder attempts: 180.
- Exact oracle matches: 0.
- Pass601 source candidates reviewed.
- aion-proxy shifted-offset variant tested: 0 matches.
- Current blocker: no EuroAion/comparable code-side transform/key evidence.

## Hard rules

No live process, debugger, memory dump, injection, anti-cheat bypass, packet injection, or running unknown binaries.
Static/offline analysis only.
