import csv
import struct
from pathlib import Path

# Bounded transforms based on handler semantics:
# 1. Bytewise XOR with 0xC7 (found in handler 0x11B57437)
# 2. Bytewise addition/subtraction variations (add_sub class)
# Let's write a targeted script to extract the KXSEQ payloads and test these transforms.

def parse_pcapng(pcap_path: Path):
    data = pcap_path.read_bytes()
    offset = 0
    packets = []
    while offset + 8 <= len(data):
        block_type, block_len = struct.unpack_from("<II", data, offset)
        if block_len == 0 or offset + block_len > len(data):
            break
        if block_type == 0x00000006:
            epb_data = data[offset + 8:offset + block_len - 4]
            cap_len = struct.unpack_from("<I", epb_data, 12)[0]
            pkt_data = epb_data[20:20 + cap_len]
            packets.append(pkt_data)
        offset += block_len
    return packets

def extract_tcp_payloads(packets):
    payloads = []
    for pkt in packets:
        if len(pkt) < 54:
            continue
        # check if TCP
        if pkt[12:14] == b"\x08\x00": # IPv4
            ihl = (pkt[14] & 0x0F) * 4
            proto = pkt[23]
            if proto == 6: # TCP
                tcp_offset = 14 + ihl
                data_offset = (pkt[tcp_offset + 12] >> 4) * 4
                payload = pkt[tcp_offset + data_offset:]
                if payload:
                    payloads.append(payload)
    return payloads

def test_transforms(payloads):
    trials = []
    # Known plaintext needle to look for (e.g. "KXSEQ")
    needle = "KXSEQ".encode("utf-16le")
    
    for p_idx, payload in enumerate(payloads[:30]):
        # Test transforms over body offsets 4, 6, 8, 10
        for offset in [4, 6, 8, 10]:
            body = payload[offset:]
            if not body:
                continue
            
            # Candidate 1: XOR 0xC7
            xored = bytes(b ^ 0xc7 for b in body)
            if needle in xored:
                trials.append({"trial_id": f"p{p_idx}_off{offset}_xor_c7", "status": "success", "notes": "Plaintext recovered!"})
                print(f"SUCCESS: XOR 0xC7 recovered needle at offset {offset}!")
            else:
                trials.append({"trial_id": f"p{p_idx}_off{offset}_xor_c7", "status": "failed", "notes": "No match"})
                
            # Candidate 2: rolling addition/subtraction
            # Let's test a simple shift or XOR with index
            idx_xor = bytes(b ^ (i & 0xff) for i, b in enumerate(body))
            if needle in idx_xor:
                trials.append({"trial_id": f"p{p_idx}_off{offset}_idx_xor", "status": "success", "notes": "Plaintext recovered!"})
            else:
                trials.append({"trial_id": f"p{p_idx}_off{offset}_idx_xor", "status": "failed", "notes": "No match"})
                
    return trials

def main():
    pcap_path = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\startup_world_open_kxseq.pcapng")
    if not pcap_path.exists():
        print("PCAP not found!")
        return
    pkts = parse_pcapng(pcap_path)
    payloads = extract_tcp_payloads(pkts)
    print(f"Extracted {len(payloads)} TCP payloads.")
    
    trials = test_transforms(payloads)
    
    out_csv = Path(r"C:\AionTools\aion_decoder_agent\outbox\pass610_antigravity_vm_cleartext_local\handler_derived_trials_full.csv")
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["trial_id", "status", "notes"])
        for t in trials:
            writer.writerow([t["trial_id"], t["status"], t["notes"]])
            
    print(f"handler_derived_trials_full.csv written with {len(trials)} trials.")

if __name__ == "__main__":
    main()
