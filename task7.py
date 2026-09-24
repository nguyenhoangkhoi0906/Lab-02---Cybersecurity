"""Task 7 -- Breaking the shift register (Lab 02, IT4010E)."""


def strxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class ShiftRegister:
    def __init__(self, n: int, taps, seed: int):
        if seed == 0:
            raise ValueError("seed must not be 0")
        self.n = n
        self.taps = taps
        self.mask = (1 << n) - 1
        self.row = seed & self.mask

    def step(self) -> int:
        out_bit = self.row & 1
        fb = 0
        for t in self.taps:
            fb ^= (self.row >> t) & 1
        self.row = (self.row >> 1) | (fb << (self.n - 1))
        return out_bit

    def keystream(self, nbytes: int) -> bytes:
        out = bytearray(nbytes)
        for i in range(nbytes):
            b = 0
            for bit_pos in range(8):
                b |= self.step() << bit_pos
            out[i] = b
        return bytes(out)


def berlekamp_massey(s):
    """Shortest LFSR (over GF(2)) generating the bit sequence s.
    Returns (L, C) with C[0] = 1 and s[i] = xor_{j=1}^{L} C[j] * s[i-j] for i >= L.
    """
    n = len(s)
    C = [1] + [0] * n
    B = [1] + [0] * n
    L, m = 0, 1
    for i in range(n):
        d = s[i]
        for j in range(1, L + 1):
            d ^= C[j] & s[i - j]
        if d == 0:
            m += 1
        elif 2 * L <= i:
            T = C.copy()
            for j in range(len(B)):
                if j + m < len(C):
                    C[j + m] ^= B[j]
            L = i + 1 - L
            B = T
            m = 1
        else:
            for j in range(len(B)):
                if j + m < len(C):
                    C[j + m] ^= B[j]
            m += 1
    return L, C[:L + 1]


CIPHER7 = bytes.fromhex(
    "3d5cae3331120fe78d2359b8998d846d5230dc78741f3880d0e36e3fb46597964"
    "a5841c015c4e29f25bbdcb0f946993cd2af3984176325a9688ab8ab6d07dfda"
    "f2f680eee88923ccc31738ce4c3c9962a5b92873b3064e64a69054def9c71331"
)
KNOWN_PLAIN = b"From: ex"


def main():
    print("ciphertext length =", len(CIPHER7), "bytes")

    known_ks_bytes = strxor(CIPHER7[:len(KNOWN_PLAIN)], KNOWN_PLAIN)
    known_bits = []
    for byte in known_ks_bytes:
        for bit_pos in range(8):
            known_bits.append((byte >> bit_pos) & 1)
    print("known output bits (64) =", known_bits)

    print("\n--- Recovering the seed (taps known: {0,10,30,31}, n=32) ---")
    seed = 0
    for j in range(32):
        seed |= known_bits[j] << j
    print(f"recovered seed = {seed:08x}")

    reg_check = ShiftRegister(32, {0, 10, 30, 31}, seed)
    check_bytes = reg_check.keystream(len(KNOWN_PLAIN))
    print("keystream check matches known bytes?", check_bytes == known_ks_bytes)

    print("\n--- Decrypting the full ciphertext ---")
    reg_full = ShiftRegister(32, {0, 10, 30, 31}, seed)
    keystream_full = reg_full.keystream(len(CIPHER7))
    message = strxor(CIPHER7, keystream_full)
    print(message.decode())

    print("\n=== Bonus: recovering without knowing the taps ===")
    L_found, C_found = berlekamp_massey(known_bits)
    print("recovered register length L =", L_found)
    print("recovered connection polynomial C =", C_found)

    total_bits_needed = len(CIPHER7) * 8
    ext_bits = list(known_bits)
    for i in range(len(ext_bits), total_bits_needed):
        val = 0
        for j in range(1, L_found + 1):
            val ^= C_found[j] & ext_bits[i - j]
        ext_bits.append(val)

    ext_keystream = bytearray(len(CIPHER7))
    for i in range(len(CIPHER7)):
        b = 0
        for bit_pos in range(8):
            b |= ext_bits[8 * i + bit_pos] << bit_pos
        ext_keystream[i] = b
    ext_keystream = bytes(ext_keystream)

    message_bonus = strxor(CIPHER7, ext_keystream)
    print(message_bonus.decode())
    print("\nmatches the taps-based decryption?", message_bonus == message)


if __name__ == "__main__":
    main()
