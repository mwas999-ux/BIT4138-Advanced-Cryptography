import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


# ── 1. Key Generation ──
def generate_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode())
    return key, salt


def aes_encrypt(plaintext, key):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext


def aes_decrypt(iv, ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode()


# ── 4. File Encryption ──
def encrypt_file(filepath, key):
    with open(filepath, "rb") as f:
        data = f.read()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    with open(filepath + ".enc", "wb") as f:
        f.write(iv + encrypted)
    return filepath + ".enc"


def decrypt_file(filepath, key):
    with open(filepath, "rb") as f:
        data = f.read()
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    with open(filepath.replace(".enc", ".dec"), "wb") as f:
        f.write(plaintext)
    return filepath.replace(".enc", ".dec")


# ── MAIN ──

# Fig 2: Key Generation
print("=" * 45)
print("         KEY GENERATION PROCESS")
print("=" * 45)
password = "SecurePass123"
key, salt = generate_key(password)
print(f"  Password     : {password}")
print(f"  Salt         : {salt.hex()}")
print(f"  Derived Key  : {key.hex()}")
print(f"  Key Size     : {len(key) * 8} bits (AES-256)")
print(f"  Algorithm    : PBKDF2 + SHA256, 100000 iterations")

# Fig 1 & 4: AES Encryption and Decryption
print("\n" + "=" * 45)
print("         AES ENCRYPTION & DECRYPTION")
print("=" * 45)
message = "Secure Login System - AES Week 4 Test"
print(f"  Original     : {message}")
iv, ciphertext = aes_encrypt(message, key)
print(f"  IV           : {iv.hex()}")
print(f"  Encrypted    : {ciphertext.hex()}")
decrypted = aes_decrypt(iv, ciphertext, key)
print(f"  Decrypted    : {decrypted}")
print(f"  Mode         : AES-256-CBC with PKCS7 Padding")

# Fig 3: File Encryption
print("\n" + "=" * 45)
print("         FILE ENCRYPTION DEMO")
print("=" * 45)
with open("testfile.txt", "w") as f:
    f.write("This is a secret file for the Secure Login System.")
print(f"  Original File    : testfile.txt")
enc_path = encrypt_file("testfile.txt", key)
print(f"  Encrypted File   : {enc_path}")
dec_path = decrypt_file(enc_path, key)
print(f"  Decrypted File   : {dec_path}")
with open(dec_path, "r") as f:
    content = f.read()
print(f"  Recovered Content: {content}")

# Fig 5: Performance Testing
print("\n" + "=" * 45)
print("         AES PERFORMANCE TEST")
print("=" * 45)
test_message = "A" * 10000
start = time.time()
for _ in range(100):
    iv, ct = aes_encrypt(test_message, key)
    aes_decrypt(iv, ct, key)
end = time.time()
print(f"  Message Size     : {len(test_message)} characters")
print(f"  Iterations       : 100 encrypt + decrypt cycles")
print(f"  Total Time       : {end - start:.4f} seconds")
print(f"  Avg Per Cycle    : {(end - start) / 100 * 1000:.4f} ms")
print(f"  Performance      : AES-256-CBC is fast and secure")
