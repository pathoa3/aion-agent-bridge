from __future__ import annotations

from functools import lru_cache

MASK32 = 0xFFFFFFFF
_WORD_COUNT = 18 + 4 * 256
_HEX_DIGITS_NEEDED = _WORD_COUNT * 8
_DECIMAL_DIGITS = 10200


def _atan_inv_scaled(q: int, scale: int) -> int:
    q2 = q * q
    term = scale // q
    total = term
    sign = -1
    k = 1
    while True:
        term //= q2
        if term == 0:
            break
        add = term // (2 * k + 1)
        if add == 0:
            break
        total = total - add if sign < 0 else total + add
        sign *= -1
        k += 1
    return total


@lru_cache(maxsize=1)
def _pi_hex_digits() -> str:
    scale = 10 ** _DECIMAL_DIGITS
    # Machin formula: pi = 16 atan(1/5) - 4 atan(1/239).
    pi_scaled = 16 * _atan_inv_scaled(5, scale) - 4 * _atan_inv_scaled(239, scale)
    frac = pi_scaled - 3 * scale
    out = []
    for _ in range(_HEX_DIGITS_NEEDED):
        frac *= 16
        digit = frac // scale
        out.append("0123456789abcdef"[int(digit)])
        frac -= digit * scale
    return "".join(out)


@lru_cache(maxsize=1)
def initial_boxes() -> tuple[list[int], list[list[int]]]:
    hx = _pi_hex_digits()
    words = [int(hx[i:i + 8], 16) for i in range(0, len(hx), 8)]
    p = words[:18]
    rest = words[18:]
    s = [rest[i * 256:(i + 1) * 256] for i in range(4)]
    return p, s


class Blowfish:
    def __init__(self, key: bytes):
        if not (4 <= len(key) <= 56):
            raise ValueError("Blowfish key length must be 4..56 bytes")
        p0, s0 = initial_boxes()
        self.p = p0[:]
        self.s = [box[:] for box in s0]
        j = 0
        for i in range(18):
            word = 0
            for _ in range(4):
                word = ((word << 8) | key[j]) & MASK32
                j = (j + 1) % len(key)
            self.p[i] ^= word
        l = 0
        r = 0
        for i in range(0, 18, 2):
            l, r = self.encrypt_lr(l, r)
            self.p[i] = l
            self.p[i + 1] = r
        for box in range(4):
            for i in range(0, 256, 2):
                l, r = self.encrypt_lr(l, r)
                self.s[box][i] = l
                self.s[box][i + 1] = r

    def f(self, x: int) -> int:
        a = (x >> 24) & 0xFF
        b = (x >> 16) & 0xFF
        c = (x >> 8) & 0xFF
        d = x & 0xFF
        y = (self.s[0][a] + self.s[1][b]) & MASK32
        y ^= self.s[2][c]
        y = (y + self.s[3][d]) & MASK32
        return y

    def encrypt_lr(self, l: int, r: int) -> tuple[int, int]:
        for i in range(16):
            l ^= self.p[i]
            r ^= self.f(l)
            l, r = r, l
        l, r = r, l
        r ^= self.p[16]
        l ^= self.p[17]
        return l & MASK32, r & MASK32

    def decrypt_lr(self, l: int, r: int) -> tuple[int, int]:
        for i in range(17, 1, -1):
            l ^= self.p[i]
            r ^= self.f(l)
            l, r = r, l
        l, r = r, l
        r ^= self.p[1]
        l ^= self.p[0]
        return l & MASK32, r & MASK32

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 8:
            raise ValueError("Blowfish block must be 8 bytes")
        l = int.from_bytes(block[:4], "big")
        r = int.from_bytes(block[4:], "big")
        l, r = self.encrypt_lr(l, r)
        return l.to_bytes(4, "big") + r.to_bytes(4, "big")

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 8:
            raise ValueError("Blowfish block must be 8 bytes")
        l = int.from_bytes(block[:4], "big")
        r = int.from_bytes(block[4:], "big")
        l, r = self.decrypt_lr(l, r)
        return l.to_bytes(4, "big") + r.to_bytes(4, "big")

    def encrypt_ecb(self, data: bytes) -> bytes:
        if len(data) % 8:
            raise ValueError("ECB data length must be multiple of 8")
        return b"".join(self.encrypt_block(data[i:i + 8]) for i in range(0, len(data), 8))

    def decrypt_ecb(self, data: bytes) -> bytes:
        if len(data) % 8:
            raise ValueError("ECB data length must be multiple of 8")
        return b"".join(self.decrypt_block(data[i:i + 8]) for i in range(0, len(data), 8))


TEST_VECTORS = [
    ("0000000000000000", "0000000000000000", "4ef997456198dd78"),
    ("ffffffffffffffff", "ffffffffffffffff", "51866fd5b85ecb8a"),
    ("3000000000000000", "1000000000000001", "7d856f9a613063f2"),
]


def selftest_rows() -> list[dict[str, object]]:
    rows = []
    for key_hex, plain_hex, cipher_hex in TEST_VECTORS:
        bf = Blowfish(bytes.fromhex(key_hex))
        enc = bf.encrypt_ecb(bytes.fromhex(plain_hex))
        dec = bf.decrypt_ecb(bytes.fromhex(cipher_hex))
        rows.append({
            "key_hex": key_hex,
            "plaintext_hex": plain_hex,
            "expected_ciphertext_hex": cipher_hex,
            "actual_ciphertext_hex": enc.hex(),
            "encrypt_ok": "yes" if enc.hex() == cipher_hex else "no",
            "decrypt_ok": "yes" if dec.hex() == plain_hex else "no",
            "roundtrip_ok": "yes" if bf.decrypt_ecb(enc).hex() == plain_hex else "no",
        })
    return rows


if __name__ == "__main__":
    rows = selftest_rows()
    for row in rows:
        print(row)
    if not all(r["encrypt_ok"] == "yes" and r["decrypt_ok"] == "yes" and r["roundtrip_ok"] == "yes" for r in rows):
        raise SystemExit(1)
