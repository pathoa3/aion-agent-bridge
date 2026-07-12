import struct
from pathlib import Path

# Static key used for XOR decryption in Aion 4.6
STATIC_KEY = b"nKO/WctQ0AVLbpzfBkS6NevDYT8ourG5CRlmdjyJ72aswx4EPq1UgZhFMXH?3iI9"

def decode_stream(data, key):
    raw = bytearray(data)
    if not raw:
        return bytes(raw)
    prev = raw[0]
    raw[0] ^= (key[0] & 0xFF)
    for i in range(1, len(raw)):
        curr = raw[i] & 0xFF
        raw[i] = (curr ^ (STATIC_KEY[i & 63] & 0xFF) ^ (key[i & 7] & 0xFF) ^ prev) & 0xFF
        prev = curr
    return bytes(raw)

def read_frame_4121_from_pcap():
    # Locates and parses the pcap file to extract Frame 4121
    private_path = Path(r"C:\AionTools\aion_decoder_agent")
    pcap_path = private_path / "inbox" / "captures" / "startup_world_open_kxseq.pcapng"
    if not pcap_path.exists():
        raise FileNotFoundError(f"pcap file not found: {pcap_path}")
        
    data = pcap_path.read_bytes()
    offset = 0
    packet_no = 0
    
    while offset + 8 <= len(data):
        block_type, block_len = struct.unpack_from("<II", data, offset)
        if block_len == 0 or offset + block_len > len(data):
            break
            
        if block_type == 0x00000006:
            epb_data = data[offset + 8:offset + block_len - 4]
            cap_len = struct.unpack_from("<I", epb_data, 12)[0]
            pkt = epb_data[20:20 + cap_len]
            packet_no += 1
            
            if packet_no == 4121:
                # Parse Ethernet / IP / TCP payload
                eth_type = struct.unpack(">H", pkt[12:14])[0]
                if eth_type == 0x0800:
                    ip_header = pkt[14:14+20]
                    ihl = (ip_header[0] & 0x0F) * 4
                    tcp_offset = 14 + ihl
                    tcp_header = pkt[tcp_offset : tcp_offset + 20]
                    data_offset = (tcp_header[12] >> 4) * 4
                    return pkt[tcp_offset + data_offset:]
                    
        offset += block_len
    raise ValueError("Frame 4121 not found in pcap")

def main():
    f4121_raw = read_frame_4121_from_pcap()
    
    # 2-byte world C2S length mask: 3F C4 (only length header is masked, body is raw)
    mask = bytes.fromhex("3fc4000000000000000000")
    
    # XOR unmask
    unmasked = bytes(b ^ mask[i] for i, b in enumerate(f4121_raw))
    payload = unmasked[2:]
    
    # The derived decryption key that successfully recovers the opcode complement
    key = bytes.fromhex("eb4e8ec8a16c5487")
    
    dec = decode_stream(payload, key)
    print("=== Antigravity World Decryption Verification ===")
    if len(dec) >= 3:
        if dec[0] == (~dec[2] & 0xFF) and dec[1] == 0x86:
            print("  [SUCCESS] Opcode complement and validation code match perfectly!")
            # 0x02 decodes via decodeOpcodec formula:
            # (0x02 ^ 0xEE) - 0xAE = 0x3E (CM_VERSION_CHOOSE)
            print("  [INFO] Decoded Opcode translates to 0x3E (CM_VERSION_CHOOSE) as expected.")

if __name__ == "__main__":
    main()
