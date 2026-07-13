from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
REPO = THIS_DIR.parents[1]
sys.path.insert(0, str(REPO / "tools" / "pass645_10242_oracle_analysis"))
from pcap_metadata import parse_pcapng, write_csv

DEFAULT_PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
DEFAULT_OUT = REPO / "artifacts" / "pass638_dynamic_flow_context.csv"


def report(pcap: Path, out: Path) -> dict:
    packets = parse_pcapng(pcap)
    ports = Counter()
    for pkt in packets:
        if pkt.server_port:
            ports[pkt.server_port] += 1
    capture_mode = "10242-only capture" if ports.get(10242, 0) and not ports.get(7785, 0) else "dynamic multi-flow capture"
    rows = []
    for port in (7785, 10242, 2106):
        rows.append({
            "server_port": port,
            "packet_count": ports.get(port, 0),
            "flow_present": str(ports.get(port, 0) > 0).lower(),
            "capture_mode": capture_mode,
            "message": "No 7785 world flow present; available 10242 chat-sidechannel flow should be analyzed first." if port == 7785 and not ports.get(7785, 0) and ports.get(10242, 0) else "available flow reported dynamically",
        })
    write_csv(out, rows, ["server_port", "packet_count", "flow_present", "capture_mode", "message"])
    return {"capture_mode": capture_mode, "ports_seen": dict(ports)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Report available capture flows so Pass638-era analyzers do not silently stop at zero 7785 packets.")
    parser.add_argument("--pcap", type=Path, default=DEFAULT_PCAP)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    summary = report(args.pcap, args.out)
    print(f"pass638_dynamic_flow_context capture_mode={summary['capture_mode']}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

