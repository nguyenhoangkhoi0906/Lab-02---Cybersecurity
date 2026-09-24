"""Task 1 -- One-time pad (Lab 02, IT4010E)."""
import os

M1 = b"Send the final report to the dean before Friday noon."
M2 = b"The exam for the course starts at eight in room D9."
M3 = b"Lunch will be served in the main hall at half past twelve."
MSGS = [M1, M2, M3]


def random_bytes(size=16):
    # os.urandom() reads from the same OS CSPRNG source as /dev/urandom
    # on Linux, and also works on Windows, where /dev/urandom does not exist.
    return os.urandom(size)


def strxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(key: bytes, msg: bytes) -> bytes:
    c = strxor(key, msg)
    print(c.hex())
    return c


def encrypt_checked(key: bytes, msg: bytes) -> bytes:
    if len(msg) > len(key):
        raise ValueError(
            f"message ({len(msg)} bytes) longer than key ({len(key)} bytes)"
        )
    return encrypt(key, msg)


def decrypt(key: bytes, c: bytes) -> bytes:
    return strxor(key, c)


def main():
    key = random_bytes(1024)
    print("key =", key.hex())

    print("\n--- Encrypting M1, M2, M3 ---")
    ciphertexts = [encrypt(key, msg) for msg in MSGS]

    with open("ciphertexts.txt", "w") as f:
        for c in ciphertexts:
            f.write(c.hex() + "\n")
    print("\nSaved ciphertexts to ciphertexts.txt")

    print("\n--- Decrypting ---")
    for c in ciphertexts:
        p = decrypt(key, c)
        print(p.decode())

    print("\n--- Encrypting a 1500-byte message with a 1024-byte key ---")
    long_msg = ((M1 + b" " + M2 + b" " + M3 + b" ") * 10)[:1500]
    print("len(msg) =", len(long_msg))
    c_long = encrypt(key, long_msg)
    print("len(ciphertext) =", len(c_long))

    p_long = decrypt(key, c_long)
    print("decrypted back:", p_long.decode())
    print("=> only the first", len(p_long), "bytes of the message survived,",
          "the rest was silently dropped by strxor/zip.")

    print("\n--- Same message, but with encrypt_checked (refuses a message longer than the key) ---")
    try:
        encrypt_checked(key, long_msg)
    except ValueError as e:
        print("Rejected:", e)


if __name__ == "__main__":
    main()
