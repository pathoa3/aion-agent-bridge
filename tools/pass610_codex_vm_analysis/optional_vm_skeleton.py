from __future__ import annotations

class VMEmulationBlocked(RuntimeError):
    pass


def decode_opcode(raw_byte: int, bl: int) -> tuple[int, int]:
    value = ((raw_byte - bl + 0x86) & 0xFF) ^ 0x34
    opcode = ((value << 5) | (value >> 3)) & 0xFF
    next_bl = (bl - opcode) & 0xFF
    return opcode, next_bl


def main() -> None:
    raise VMEmulationBlocked(
        "Current exports lack pass8b_handler_table_from_ghidra.csv, "
        "pass8b_target_pcode.txt, and a file-backed VM bytecode slice. "
        "This skeleton intentionally performs no client execution or runtime extraction."
    )


if __name__ == "__main__":
    main()
