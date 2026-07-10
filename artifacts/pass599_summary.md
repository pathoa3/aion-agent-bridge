# Pass599 summary

PCAP extraction audit found and fixed an 8-byte stripping bug.

- Raw frame 7166 length: 22
- Correct model: UTF-16LE byte length + 10
- Wrong model: UTF-16LE byte length + 2
- Root cause: TCP header length computed from an invalid combined field
- Correct logic: `tcp_hlen = (pkt[tcp_off + 12] >> 4) * 4`

No decoder success claimed.
