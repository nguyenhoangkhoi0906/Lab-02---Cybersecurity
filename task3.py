"""Task 3 -- A pseudorandom pad from NaCl (Lab 02, IT4010E)."""
import nacl.secret
import nacl.utils

M1 = b"Send the final report to the dean before Friday noon."
M2 = b"The exam for the course starts at eight in room D9."


def strxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def G(key: bytes, nonce: bytes, n: int) -> bytes:
    box = nacl.secret.SecretBox(key)
    #box.encrypt(data, nonce).ciphertext = 16-byte tag || (data xor stream)
    #with data = n zero bytes, this is tag || stream, so [16:] is the pad.
    return box.encrypt(bytes(n), nonce).ciphertext[16:]


def encrypt(key: bytes, msg: bytes) -> bytes:
    nonce = nacl.utils.random(24)
    pad = G(key, nonce, len(msg))
    return nonce + strxor(msg, pad)


def decrypt(key: bytes, c: bytes) -> bytes:
    nonce, body = c[:24], c[24:]
    pad = G(key, nonce, len(body))
    return strxor(body, pad)


def main():
    key = nacl.utils.random(32)
    nonce = nacl.utils.random(24)
    print("key   =", key.hex())
    print("nonce =", nonce.hex())
    print("G(k, nonce, 64) =", G(key, nonce, 64).hex())

    print("\n--- Encrypting M1 twice (fresh random nonce each time) ---")
    c1a = encrypt(key, M1)
    c1b = encrypt(key, M1)
    print("c1a =", c1a.hex())
    print("c1b =", c1b.hex())
    print("same ciphertext?", c1a == c1b)

    p1a = decrypt(key, c1a)
    print("decrypt(c1a) =", p1a.decode())

    print("\n--- Encrypting M1 and M2 with the SAME nonce ---")
    reused_nonce = nacl.utils.random(24)
    padA = G(key, reused_nonce, len(M1))
    padB = G(key, reused_nonce, len(M2))
    cA = reused_nonce + strxor(M1, padA)
    cB = reused_nonce + strxor(M2, padB)

    bodyA, bodyB = cA[24:], cB[24:]
    x_bodies = strxor(bodyA, bodyB)
    expected = strxor(M1, M2)
    print("bodyA xor bodyB =", x_bodies.hex())
    print("M1 xor M2       =", expected.hex())
    print("equal?", x_bodies == expected)


if __name__ == "__main__":
    main()
