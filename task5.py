"""Task 5 -- Changing an encrypted amount (Lab 02, IT4010E)."""
import nacl.secret
import nacl.utils


def strxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def G(key: bytes, nonce: bytes, n: int) -> bytes:
    box = nacl.secret.SecretBox(key)
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

    print("--- Attack 1: bit-flip on our Task 3 cipher ---")
    msg = b"PAY BOB 0100 USD"
    c = encrypt(key, msg)
    print("original ciphertext =", c.hex())
    print("decrypts to          =", decrypt(key, c).decode())

    target = b"PAY BOB 9900 USD"
    delta = strxor(msg, target)  # nonzero only where the digits differ
    print("delta (msg xor target) =", delta.hex())

    c_forged = bytearray(c)
    body = strxor(bytes(c_forged[24:]), delta)  # flip only the ciphertext body
    c_forged[24:] = body
    c_forged = bytes(c_forged)

    print("forged ciphertext   =", c_forged.hex())
    print("forged decrypts to  =", decrypt(key, c_forged).decode())

    print("\n--- Attack 2: same bit-flip on a real SecretBox ciphertext ---")
    box = nacl.secret.SecretBox(key)
    box_c = box.encrypt(msg)  # layout: nonce (24B) || tag (16B) || body
    print("box ciphertext =", box_c.hex())

    box_c_forged = bytearray(box_c)
    body_offset = 24 + 16
    body2 = strxor(bytes(box_c_forged[body_offset:]), delta)
    box_c_forged[body_offset:] = body2
    box_c_forged = bytes(box_c_forged)
    print("forged box ciphertext =", box_c_forged.hex())

    try:
        result = box.decrypt(bytes(box_c_forged))
        print("box.decrypt succeeded:", result)
    except Exception as e:
        print("box.decrypt raised:", type(e).__name__, "-", e)


if __name__ == "__main__":
    main()
