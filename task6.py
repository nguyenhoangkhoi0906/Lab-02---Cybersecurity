"""Task 6 -- A shift-register generator (Lab 02, IT4010E)."""
import os


class ShiftRegister:
    def __init__(self, n: int, taps, seed: int):
        if seed == 0:
            raise ValueError("seed must not be 0 (the all-zero row never changes)")
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

    def bits(self, count: int):
        return [self.step() for _ in range(count)]

    def keystream(self, nbytes: int) -> bytes:
        out = bytearray(nbytes)
        for i in range(nbytes):
            b = 0
            for bit_pos in range(8):
                b |= self.step() << bit_pos
            out[i] = b
        return bytes(out)


def period(n: int, taps, seed: int) -> int:
    reg = ShiftRegister(n, taps, seed)
    start = reg.row
    steps = 0
    while True:
        reg.step()
        steps += 1
        if reg.row == start:
            return steps


def strxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def random_nonzero_seed(n_bits: int) -> int:
    while True:
        s = int.from_bytes(os.urandom(n_bits // 8), "big")
        if s != 0:
            return s


def main():
    print("--- Part 1: n=4, taps={0,1}, seed=1001 (9), first 16 output bits ---")
    reg = ShiftRegister(4, {0, 1}, 0b1001)
    print(reg.bits(16))

    print("\n--- Part 2: periods ---")
    print("n=4,  taps={0,1},       seed=0b1001 ->", period(4, {0, 1}, 0b1001))
    print("n=16, taps={0,2,3,5},   seed=1      ->", period(16, {0, 2, 3, 5}, 1))
    print("n=16, taps={0,8},       seed=1      ->", period(16, {0, 8}, 1))

    print("\n--- Part 3: n=32, taps={0,10,30,31}, random seed ---")
    message = (
        b"From: exam-office@example.edu\n"
        b"Subject: final exam\n"
        b"Room B1-401, 8:00 on Monday."
    )
    seed = random_nonzero_seed(32)
    reg_msg = ShiftRegister(32, {0, 10, 30, 31}, seed)
    ks = reg_msg.keystream(len(message))
    cipher = strxor(message, ks)

    print(f"seed = {seed:08x}")
    print("ciphertext =", cipher.hex())

    reg_sample = ShiftRegister(32, {0, 10, 30, 31}, seed)
    sample = reg_sample.keystream(64 * 1024)
    ones = sum(bin(b).count("1") for b in sample)
    total_bits = len(sample) * 8
    print(f"fraction of 1-bits in 64 KiB = {ones / total_bits:.4f}")


if __name__ == "__main__":
    main()
