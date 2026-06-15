#

from collections import Counter

# ── Reuse Week 6 SPN ────────────────────────────────────────
SBOX = {
    0: 14,
    1: 4,
    2: 13,
    3: 1,
    4: 2,
    5: 15,
    6: 11,
    7: 8,
    8: 3,
    9: 10,
    10: 6,
    11: 12,
    12: 5,
    13: 9,
    14: 0,
    15: 7,
}
SBOX_INV = {v: k for k, v in SBOX.items()}
PBOX = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]


def substitute(block):
    result = 0
    for i in range(4):
        nibble = (block >> (12 - i * 4)) & 0xF
        result |= SBOX[nibble] << (12 - i * 4)
    return result


def permute(block):
    result = 0
    for i, pos in enumerate(PBOX):
        bit = (block >> (15 - pos)) & 1
        result |= bit << (15 - i)
    return result


def generate_round_keys(key, num_rounds):
    return [(key ^ (i * 0x1F3A)) & 0xFFFF for i in range(num_rounds + 1)]


def spn_encrypt(plaintext, key, num_rounds=4):
    rks = generate_round_keys(key, num_rounds)
    b = plaintext
    for r in range(num_rounds):
        b ^= rks[r]
        b = substitute(b)
        if r < num_rounds - 1:
            b = permute(b)
    b ^= rks[num_rounds]
    return b


# ── Section 1: Differential Cryptanalysis Simulation ────────
def differential_analysis(p1, p2, key, num_rounds=4):
    print(f"\n{'='*56}")
    print(f"  SECTION 1: DIFFERENTIAL CRYPTANALYSIS SIMULATION")
    print(f"{'='*56}")

    input_diff = p1 ^ p2

    print(f"\n  Plaintext 1   : {p1:016b}  (0x{p1:04X} | {p1})")
    print(f"  Plaintext 2   : {p2:016b}  (0x{p2:04X} | {p2})")
    print(f"  Input XOR Diff: {input_diff:016b}  (0x{input_diff:04X})")
    print(f"  Bits Different: {bin(input_diff).count('1')} / 16")

    # Encrypt both
    c1 = spn_encrypt(p1, key, num_rounds)
    c2 = spn_encrypt(p2, key, num_rounds)
    output_diff = c1 ^ c2
    bits_changed = bin(output_diff).count("1")

    print(f"\n  Ciphertext 1  : {c1:016b}  (0x{c1:04X})")
    print(f"  Ciphertext 2  : {c2:016b}  (0x{c2:04X})")
    print(f"  Output XOR Diff:{output_diff:016b}  (0x{output_diff:04X})")
    print(f"  Bits Changed  : {bits_changed} / 16")

    # Round-by-round difference propagation
    print(f"\n  ── Difference Propagation Through Rounds ──")
    rks = generate_round_keys(key, num_rounds)
    b1, b2 = p1, p2
    for r in range(num_rounds):
        b1 ^= rks[r]
        b2 ^= rks[r]
        diff_after_key = b1 ^ b2
        b1 = substitute(b1)
        b2 = substitute(b2)
        diff_after_sub = b1 ^ b2
        if r < num_rounds - 1:
            b1 = permute(b1)
            b2 = permute(b2)
            diff_after_perm = b1 ^ b2
            print(
                f"  Round {r+1}: Key={bin(diff_after_key).count('1'):2d} bits diff │ "
                f"Sub={bin(diff_after_sub).count('1'):2d} bits diff │ "
                f"Perm={bin(diff_after_perm).count('1'):2d} bits diff"
            )
        else:
            print(
                f"  Round {r+1}: Key={bin(diff_after_key).count('1'):2d} bits diff │ "
                f"Sub={bin(diff_after_sub).count('1'):2d} bits diff │ "
                f"Perm= -- (skipped last round)"
            )

    security = "✓ STRONG diffusion" if bits_changed >= 6 else "⚠ WEAK diffusion"
    print(f"\n  Assessment    : {security} ({bits_changed}/16 bits changed)")
    print(f"{'='*56}\n")
    return c1, c2, output_diff


# ── Section 2: Algebraic Attack Demonstration ───────────────
def algebraic_attack_demo(plaintext, key):
    print(f"{'='*56}")
    print(f"  SECTION 2: ALGEBRAIC ATTACK DEMONSTRATION")
    print(f"{'='*56}")

    # Simple XOR cipher — shows how algebraic weakness works
    ciphertext = plaintext ^ key
    recovered = ciphertext ^ plaintext  # attacker knows P and C

    print(f"\n  [Simple XOR Cipher]")
    print(f"  Plaintext     : {plaintext:016b}  (0x{plaintext:04X})")
    print(f"  Secret Key    : {key:016b}  (0x{key:04X})")
    print(f"  Ciphertext    : {ciphertext:016b}  (0x{ciphertext:04X})")
    print(f"\n  [Attacker knows P and C → derives K = P XOR C]")
    print(f"  Recovered Key : {recovered:016b}  (0x{recovered:04X})")
    match = "✓ KEY RECOVERED" if recovered == key else "✗ FAILED"
    print(f"  Result        : {match}")

    print(f"\n  [Why SPN resists this]")
    print(f"  SPN Ciphertext: {spn_encrypt(plaintext, key):016b}")
    print(f"  Simple XOR C  : {ciphertext:016b}")
    print(f"  SPN adds non-linear S-Box layers — simple K=P^C fails.")
    print(f"{'='*56}\n")


# ── Section 3: Linear Cryptanalysis Simulation ──────────────
def linear_cryptanalysis_demo(key, num_samples=200):
    print(f"{'='*56}")
    print(f"  SECTION 3: LINEAR CRYPTANALYSIS SIMULATION")
    print(f"{'='*56}")
    print(f"\n  Testing linear approximation: P[0] XOR C[0] = K_bias")
    print(f"  Samples: {num_samples}")

    matches = 0
    for p in range(num_samples):
        c = spn_encrypt(p & 0xFFFF, key)
        p_bit = (p >> 15) & 1  # MSB of plaintext
        c_bit = (c >> 15) & 1  # MSB of ciphertext
        if (p_bit ^ c_bit) == 0:
            matches += 1

    probability = matches / num_samples
    bias = abs(probability - 0.5)

    print(f"\n  Matches       : {matches} / {num_samples}")
    print(f"  Probability   : {probability:.4f}")
    print(f"  Bias from 0.5 : {bias:.4f}")

    if bias < 0.05:
        assessment = "✓ LOW bias — strong resistance to linear cryptanalysis"
    elif bias < 0.15:
        assessment = "~ MODERATE bias — some linear leakage"
    else:
        assessment = "⚠ HIGH bias — vulnerable to linear cryptanalysis"

    print(f"  Assessment    : {assessment}")
    print(f"{'='*56}\n")


# ── Section 4: Frequency Analysis ───────────────────────────
def frequency_analysis(key, num_samples=256):
    print(f"{'='*56}")
    print(f"  SECTION 4: FREQUENCY ANALYSIS OF CIPHERTEXT")
    print(f"{'='*56}")
    print(f"\n  Encrypting {num_samples} sequential plaintexts...")

    ciphertexts = [spn_encrypt(i, key) for i in range(num_samples)]
    high_bytes = [(c >> 8) & 0xFF for c in ciphertexts]
    low_bytes = [c & 0xFF for c in ciphertexts]
    high_count = Counter(high_bytes)
    low_count = Counter(low_bytes)

    # Show top 5 most frequent values
    print(f"\n  Top 5 High-Byte frequencies:")
    for val, cnt in high_count.most_common(5):
        bar = "█" * cnt
        print(f"    0x{val:02X} : {cnt:3d}  {bar}")

    print(f"\n  Top 5 Low-Byte frequencies:")
    for val, cnt in low_count.most_common(5):
        bar = "█" * cnt
        print(f"    0x{val:02X} : {cnt:3d}  {bar}")

    unique_ct = len(set(ciphertexts))
    print(f"\n  Unique ciphertexts : {unique_ct} / {num_samples}")
    uniformity = (
        "✓ GOOD — high output diversity"
        if unique_ct >= num_samples * 0.9
        else "⚠ POOR — repeated ciphertext values detected"
    )
    print(f"  Assessment         : {uniformity}")
    print(f"{'='*56}\n")


# ── Section 5: Avalanche Effect (full test) ─────────────────
def avalanche_test(key, num_rounds=4):
    print(f"{'='*56}")
    print(f"  SECTION 5: AVALANCHE EFFECT TEST")
    print(f"{'='*56}")
    print(f"\n  Testing each single-bit flip in a 16-bit plaintext...")

    base = 0b1010101010101010
    total_bits = 0

    print(
        f"\n  {'Bit Flipped':>12} │ {'Input Diff':>10} │ {'Output Diff':>11} │ {'Bits Changed':>12}"
    )
    print(f"  {'-'*12}-+-{'-'*10}-+-{'-'*11}-+-{'-'*12}")

    for bit in range(16):
        flipped = base ^ (1 << bit)
        c1 = spn_encrypt(base, key, num_rounds)
        c2 = spn_encrypt(flipped, key, num_rounds)
        out_diff = c1 ^ c2
        changed = bin(out_diff).count("1")
        total_bits += changed
        print(
            f"  {'Bit '+str(bit):>12} │ {1:>10} │ 0x{out_diff:04X}      │ {changed:>12}"
        )

    avg = total_bits / 16
    print(f"\n  Average bits changed per flip: {avg:.2f} / 16")
    rating = "✓ EXCELLENT" if avg >= 7 else ("~ MODERATE" if avg >= 4 else "⚠ WEAK")
    print(f"  Avalanche rating             : {rating}")
    print(f"{'='*56}\n")


# ── Main ─────────────────────────────────────────────────────
def main():
    print("\n" + "=" * 56)
    print("  BIT4138: Advanced Cryptography")
    print("  Week 7 — Block Cipher Cryptanalysis Toolkit")
    print("  Secure Login & Authentication Project")
    print("=" * 56)

    # User inputs
    try:
        p1_in = input("\n  Enter Plaintext 1 (0–65535): ").strip()
        p2_in = input("  Enter Plaintext 2 (0–65535): ").strip()
        key_in = input("  Enter Key         (0–65535): ").strip()
        p1 = int(p1_in) & 0xFFFF
        p2 = int(p2_in) & 0xFFFF
        key = int(key_in) & 0xFFFF
    except ValueError:
        print("  [!] Invalid input — using defaults: P1=12345, P2=12344, Key=54321")
        p1, p2, key = 12345, 12344, 54321

    # Run all sections
    differential_analysis(p1, p2, key)
    algebraic_attack_demo(p1, key)
    linear_cryptanalysis_demo(key)
    frequency_analysis(key)
    avalanche_test(key)

    print("=" * 56)
    print("  Cryptanalysis complete.")
    print("=" * 56 + "\n")


if __name__ == "__main__":
    main()
