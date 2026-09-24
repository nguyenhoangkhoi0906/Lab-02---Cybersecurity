"""Task 4 -- Encrypting a book (Lab 02, IT4010E).

Requires book.pdf in the same directory:
    Invoke-WebRequest -Uri "https://toc.cryptobook.us/book.pdf" -OutFile "book.pdf"
"""
import os
import hashlib
import time

import nacl.secret
import nacl.utils

CHUNK_SIZE = 1024 * 1024  # 1 MiB


def G(key: bytes, nonce: bytes, n: int) -> bytes:
    box = nacl.secret.SecretBox(key)
    return box.encrypt(bytes(n), nonce).ciphertext[16:]


def int_xor(a: bytes, b: bytes) -> bytes:
    # XOR-ing as big integers is roughly 10x faster than a byte-by-byte
    # loop for large buffers (per the lab's tip).
    n = len(a)
    ai = int.from_bytes(a, "little")
    bi = int.from_bytes(b, "little")
    return (ai ^ bi).to_bytes(n, "little")


def encrypt_book(in_path, out_path, key, prefix=None, forget_counter=False):
    if prefix is None:
        prefix = nacl.utils.random(16)
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(prefix)
        i = 0
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            counter = 0 if forget_counter else i
            nonce = prefix + counter.to_bytes(8, "big")
            pad = G(key, nonce, len(chunk))
            fout.write(int_xor(chunk, pad))
            i += 1
    return prefix


def decrypt_book(in_path, out_path, key, forget_counter=False):
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        prefix = fin.read(16)
        i = 0
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            counter = 0 if forget_counter else i
            nonce = prefix + counter.to_bytes(8, "big")
            pad = G(key, nonce, len(chunk))
            fout.write(int_xor(chunk, pad))
            i += 1


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def main():
    book_key = nacl.utils.random(32)
    print("book key =", book_key.hex())

    print("\n--- Encrypting book.pdf -> book.enc (correct counter) ---")
    t0 = time.perf_counter()
    encrypt_book("book.pdf", "book.enc", book_key)
    t1 = time.perf_counter()
    print(f"encryption time: {t1 - t0:.3f} s")

    size_pdf = os.path.getsize("book.pdf")
    size_enc = os.path.getsize("book.enc")
    print("size(book.pdf) =", size_pdf)
    print("size(book.enc) =", size_enc)
    print("size(book.enc) - size(book.pdf) =", size_enc - size_pdf)

    with open("book.pdf", "rb") as f:
        first16_plain = f.read(16)
    with open("book.enc", "rb") as f:
        f.read(16)  # skip the random prefix
        first16_cipher = f.read(16)
    print("first 16 bytes of plaintext  =", first16_plain.hex())
    print("first 16 bytes of ciphertext =", first16_cipher.hex())

    print("SHA-256(book.pdf) =", sha256_file("book.pdf"))
    decrypt_book("book.enc", "book.dec.pdf", book_key)
    print("SHA-256(book.dec.pdf) =", sha256_file("book.dec.pdf"))
    print("match?", sha256_file("book.pdf") == sha256_file("book.dec.pdf"))

    print("\n--- Encrypting again with the counter forgotten (every chunk uses prefix || 0) ---")
    encrypt_book("book.pdf", "book.buggy.enc", book_key, forget_counter=True)

    def read_two_chunks(path, skip_prefix):
        with open(path, "rb") as f:
            f.read(skip_prefix)
            c0 = f.read(CHUNK_SIZE)
            c1 = f.read(CHUNK_SIZE)
        return c0, c1

    m0, m1 = read_two_chunks("book.pdf", skip_prefix=0)
    c0_good, c1_good = read_two_chunks("book.enc", skip_prefix=16)
    c0_bad, c1_bad = read_two_chunks("book.buggy.enc", skip_prefix=16)

    print("\nCorrect-counter version:  c0 xor c1 == m0 xor m1 ?",
          int_xor(c0_good, c1_good) == int_xor(m0, m1))
    print("Forgotten-counter version: c0 xor c1 == m0 xor m1 ?",
          int_xor(c0_bad, c1_bad) == int_xor(m0, m1))


if __name__ == "__main__":
    main()
