# Pass607 Codex Oracle Analysis

- parser: custom pcapng parser, static/offline only
- corrected TCP header length: `tcp_hlen = (pkt[tcp_off + 12] >> 4) * 4`
- oracle frames aligned: 15
- all raw C2S lengths equal UTF-16LE byte length + 10: yes
- frame 7166 raw payload length: 22
- no decoder success is claimed by extraction.
