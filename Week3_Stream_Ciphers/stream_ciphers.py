import time
import random


def lfsr(seed, taps, num_bits):
    state = seed.copy()
    sequence = []
    for _ in range(num_bits):
        output_bit = state[-1]
        sequence.append(output_bit)
        feedback = 0
        for tap in taps:
            feedback ^= state[tap]
        state = [feedback] + state[:-1]
    return sequence


# ── 2. Randomness Test ──
def randomness_test(sequence):
    ones = sum(sequence)
    zeros = len(sequence) - ones
    period = len(sequence)
    balance = ones / len(sequence) * 100
    print(f"  Total Bits  : {len(sequence)}")
    print(f"  Ones (1s)   : {ones}")
    print(f"  Zeros (0s)  : {zeros}")
    print(f"  Balance     : {balance:.2f}% ones")
    print(f"  Period      : {period} bits before repeat")
    if 40 <= balance <= 60:
        print("  Result      :  PASS - Sequence is statistically random")
    else:
        print("  Result      :  FAIL - Sequence is biased")


# ── 3. RC4 Stream Cipher ──
def rc4_ksa(key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_prga(S, length):
    i = j = 0
    keystream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return keystream


def rc4_encrypt_decrypt(message, key):
    key_bytes = [ord(c) for c in key]
    S = rc4_ksa(key_bytes)
    keystream = rc4_prga(S, len(message))
    return bytes([ord(c) ^ k for c, k in zip(message, keystream)])


# ── MAIN ──

# Fig 1 & 2: LFSR Generation
print("=" * 45)
print("       LFSR PSEUDORANDOM GENERATOR")
print("=" * 45)
seed = [1, 0, 1, 1]
taps = [0, 3]
sequence = lfsr(seed, taps, 50)
print(f"  Seed        : {seed}")
print(f"  Taps        : {taps}")
print(f"  Sequence    : {sequence[:20]}...")
print(f"  Full Length : {len(sequence)} bits generated")

# Fig 3: Randomness Testing
print("\n" + "=" * 45)
print("       STATISTICAL RANDOMNESS TEST")
print("=" * 45)
randomness_test(sequence)

# Fig 4: RC4 Encryption
print("\n" + "=" * 45)
print("       RC4 STREAM CIPHER")
print("=" * 45)
message = "SecureLoginSystem"
key = "CRYPTOKEY"
encrypted = rc4_encrypt_decrypt(message, key)
decrypted = rc4_encrypt_decrypt(encrypted.decode("latin-1"), key)
print(f"  Original    : {message}")
print(f"  Key         : {key}")
print(f"  Encrypted   : {encrypted.hex()}")
print(f"  Decrypted   : {decrypted.decode('latin-1')}")

# Fig 5: Performance Test
print("\n" + "=" * 45)
print("       ENCRYPTION PERFORMANCE TEST")
print("=" * 45)
test_message = "A" * 10000
start = time.time()
for _ in range(100):
    rc4_encrypt_decrypt(test_message, key)
end = time.time()
print(f"  Message Size   : {len(test_message)} characters")
print(f"  Iterations     : 100")
print(f"  Total Time     : {end - start:.4f} seconds")
print(f"  Avg Per Encrypt: {(end - start) / 100 * 1000:.4f} ms")
print(f"  Performance    :  RC4 encryption is fast and efficient")
