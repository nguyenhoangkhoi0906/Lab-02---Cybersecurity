"""Task 2 -- Reusing the pad (Lab 02, IT4010E)."""

M1 = b"Send the final report to the dean before Friday noon."
M2 = b"The exam for the course starts at eight in room D9."
M3 = b"Lunch will be served in the main hall at half past twelve."


def strxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def decrypt(key: bytes, c: bytes) -> bytes:
    return strxor(key, c)


def is_lower_or_space(data: bytes) -> bool:
    return all((97 <= b <= 122) or b == 32 for b in data)


def load_ciphertexts(path="ciphertexts.txt"):
    with open(path) as f:
        lines = [line.strip() for line in f if line.strip()]
    return [bytes.fromhex(line) for line in lines]


def main():
    c1, c2, c3 = load_ciphertexts()

    #1. c1 xor c2 
    print("--- Step 1: c1 xor c2 ---")
    x12 = strxor(c1, c2)
    print("c1 xor c2 =", x12.hex())

    expected = strxor(M1, M2)
    print("M1 xor M2 =", expected.hex())
    print("equal?", x12 == expected)

    #2. Crib dragging with " the " 
    print("\n--- Step 2: crib dragging with \" the \" ---")
    crib = b" the "
    for i in range(len(x12) - len(crib) + 1):
        candidate = strxor(x12[i:i + len(crib)], crib)
        if is_lower_or_space(candidate):
            print(f"position {i:2d}: {candidate.decode()!r}")

    #3. Forge a key k' so that c1 decrypts to a chosen message 
    print("\n--- Step 3: forge a key for c1 ---")
    target = b"Nothing to see here."
    if len(target) < len(c1):
        target_padded = target + b" " * (len(c1) - len(target))
    else:
        target_padded = target[:len(c1)]

    k_prime = strxor(c1, target_padded)
    print("k' =", k_prime.hex())

    check = decrypt(k_prime, c1)
    print("decrypt(k', c1) =", check.decode())
    print("matches target?", check == target_padded)


if __name__ == "__main__":
    main()
