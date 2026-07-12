#!/usr/bin/env python3
"""Future S2C oracle scaffold.

This script intentionally does not embed or commit packet payloads. It records only the
shape of a future S2C known-plaintext oracle request so a local-only decoder run can
later derive/check frame-local key state without exposing private capture bytes.
"""
import argparse, csv, json
from pathlib import Path

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--frame-number', required=True)
    ap.add_argument('--known-text', required=True)
    ap.add_argument('--direction', default='S2C')
    ap.add_argument('--capture-label', default='startup_or_world_entry')
    ap.add_argument('--local-output', default=r'C:\AionTools\aion_decoder_agent\outbox\pass634_s2c_oracle_local\oracle_request.json')
    ns=ap.parse_args()
    if ns.direction.upper() != 'S2C':
        raise SystemExit('Pass634 oracle scaffold accepts S2C only')
    p=Path(ns.local_output); p.parent.mkdir(parents=True, exist_ok=True)
    record={
        'frame_number': ns.frame_number,
        'direction': 'S2C',
        'capture_label': ns.capture_label,
        'known_text_length_chars': len(ns.known_text),
        'known_utf16le_length_bytes': len(ns.known_text.encode('utf-16le')),
        'payload_bytes_stored': False,
        'packet_hash_stored': False,
        'next_local_step': 'pair this metadata with local PCAP bytes and a concrete S2C transform/key schedule; do not commit derived bytes or hashes'
    }
    p.write_text(json.dumps(record, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'written': str(p), 'payload_bytes_stored': False}))

if __name__ == '__main__':
    main()
