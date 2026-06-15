# spn_implementation.py
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

# Inverse S-Box for decryption
SBOX_INV = {v: k for k, v in SBOX.items()}

# --- Permutation Table ---
# Rearranges bit positions across a 16-bit block
PBOX = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]


def substitute(block):
    """Apply S-Box substitution to a 16-bit block (four 4-bit nibbles)."""
    result = 0
    for i in range(4):
        nibble = (block >> (12 - i * 4)) & 0xF
        substituted = SBOX[nibble]
        result |= substituted << (12 - i * 4)
    return result


def permute(block):
    """Apply P-Box permutation to a 16-bit block."""
    result = 0
    for i, pos in enumerate(PBOX):
        bit = (block >> (15 - pos)) & 1
        result |= bit << (15 - i)
    return result


def generate_round_keys(key, num_rounds):
    """Derive round keys from the main 16-bit key."""
    round_keys = []
    for i in range(num_rounds + 1):
        rk = (key ^ (i * 0x1F3A)) & 0xFFFF
        round_keys.append(rk)
    return round_keys


def spn_encrypt(plaintext, key, num_rounds=4):
    """Encrypt a 16-bit plaintext block using SPN."""
    round_keys = generate_round_keys(key, num_rounds)
    block = plaintext

    print(f"\n{'='*50}")
    print(f"  SPN ENCRYPTION  |  Rounds: {num_rounds}")
    print(f"{'='*50}")
    print(f"  Plaintext  : {plaintext:016b} (0x{plaintext:04X})")
    print(f"  Key        : {key:016b} (0x{key:04X})")
    print(f"{'='*50}")

    for r in range(num_rounds):
        # Key mixing
        block ^= round_keys[r]
        print(f"\n  [Round {r+1}]")
        print(f"    After Key Mix    : {block:016b} (0x{block:04X})")

        # Substitution
        block = substitute(block)
        print(f"    After S-Box      : {block:016b} (0x{block:04X})")

        # Permutation (skip on last round)
        if r < num_rounds - 1:
            block = permute(block)
            print(f"    After Permutation: {block:016b} (0x{block:04X})")

    # Final key mixing
    block ^= round_keys[num_rounds]
    print(f"\n  Final Key Mix    : {block:016b} (0x{block:04X})")
    print(f"{'='*50}")
    print(f"  Ciphertext : {block:016b} (0x{block:04X})")
    print(f"{'='*50}\n")
    return block


def inv_permute(block):
    """Apply inverse P-Box permutation to a 16-bit block."""
    result = 0
    for i, pos in enumerate(PBOX):
        bit = (block >> (15 - i)) & 1
        result |= bit << (15 - pos)
    return result


def inv_substitute(block):
    """Apply inverse S-Box substitution to a 16-bit block."""
    result = 0
    for i in range(4):
        nibble = (block >> (12 - i * 4)) & 0xF
        result |= SBOX_INV[nibble] << (12 - i * 4)
    return result


def spn_decrypt(ciphertext, key, num_rounds=4):
    """Decrypt a 16-bit ciphertext block using inverse SPN operations.

    Encryption per round r (0 to N-1):
      XOR round_key[r] -> Substitute -> Permute (skipped on last round)
    Then final XOR round_key[N].

    Decryption reverses this exactly:
      Undo final XOR -> for r=N-1 down to 0:
        Undo Permute (if r < N-1) -> Undo Substitute -> Undo XOR round_key[r]
    """
    round_keys = generate_round_keys(key, num_rounds)
    block = ciphertext

    print(f"\n{'='*50}")
    print(f"  SPN DECRYPTION  |  Rounds: {num_rounds}")
    print(f"{'='*50}")
    print(f"  Ciphertext : {ciphertext:016b} (0x{ciphertext:04X})")
    print(f"{'='*50}")

    # Undo final key mix
    block ^= round_keys[num_rounds]
    print(f"\n  Undo Final Key Mix : {block:016b} (0x{block:04X})")

    for r in range(num_rounds - 1, -1, -1):
        print(f"\n  [Round {r+1}]")

        # Undo permutation first (it was the last operation in that round)
        # Last encryption round (r = num_rounds-1) had NO permutation
        if r < num_rounds - 1:
            block = inv_permute(block)
            print(f"    After Inv P-Box  : {block:016b} (0x{block:04X})")

        # Undo substitution
        block = inv_substitute(block)
        print(f"    After Inv S-Box  : {block:016b} (0x{block:04X})")

        # Undo key mix (it was the first operation in that round)
        block ^= round_keys[r]
        print(f"    After Key Mix    : {block:016b} (0x{block:04X})")

    print(f"\n{'='*50}")
    print(f"  Decrypted  : {block:016b} (0x{block:04X})")
    print(f"{'='*50}\n")
    return block


def avalanche_test(key, num_rounds=4):
    """Demonstrate the avalanche effect: 1-bit change in plaintext."""
    print(f"\n{'='*50}")
    print(f"  AVALANCHE EFFECT TEST")
    print(f"{'='*50}")

    p1 = 0b1010101010101010
    p2 = 0b1010101010101011  # only last bit differs

    c1 = spn_encrypt(p1, key, num_rounds)
    c2 = spn_encrypt(p2, key, num_rounds)

    diff = c1 ^ c2
    bits_changed = bin(diff).count("1")

    print(f"  Plaintext 1  : {p1:016b}")
    print(f"  Plaintext 2  : {p2:016b}")
    print(f"  Ciphertext 1 : {c1:016b}")
    print(f"  Ciphertext 2 : {c2:016b}")
    print(f"  XOR Diff     : {diff:016b}")
    print(f"  Bits Changed : {bits_changed} / 16")
    print(f"{'='*50}\n")


def display_sbox():
    """Display the S-Box lookup table."""
    print(f"\n{'='*50}")
    print(f"  S-BOX LOOKUP TABLE")
    print(f"{'='*50}")
    print(f"  {'Input':>6} | {'Output':>6}")
    print(f"  {'-'*6}-+-{'-'*6}")
    for k, v in SBOX.items():
        print(f"  {k:>6} | {v:>6}")
    print(f"{'='*50}\n")


def main():
    print("\n" + "=" * 50)
    print("  BIT4138: Advanced Cryptography")
    print("  Week 6 - SPN Encryption System")
    print("  Secure Login & Authentication Project")
    print("=" * 50)

    # --- Display S-Box ---
    display_sbox()

    # --- User Input ---
    try:
        pt_input = input("  Enter plaintext as integer (0-65535): ")
        key_input = input("  Enter key as integer (0-65535): ")
        rounds_input = input("  Enter number of rounds (2-8, default 4): ").strip()

        plaintext = int(pt_input) & 0xFFFF
        key = int(key_input) & 0xFFFF
        num_rounds = int(rounds_input) if rounds_input else 4

    except ValueError:
        print(
            "  [!] Invalid input. Using defaults: plaintext=12345, key=54321, rounds=4"
        )
        plaintext, key, num_rounds = 12345, 54321, 4

    # --- Encryption ---
    ciphertext = spn_encrypt(plaintext, key, num_rounds)

    # --- Decryption ---
    decrypted = spn_decrypt(ciphertext, key, num_rounds)

    # --- Verify ---
    print(f"{'='*50}")
    print(f"  VERIFICATION")
    print(f"{'='*50}")
    print(f"  Original Plaintext : {plaintext} (0x{plaintext:04X})")
    print(f"  Ciphertext         : {ciphertext} (0x{ciphertext:04X})")
    print(f"  Decrypted          : {decrypted} (0x{decrypted:04X})")
    match = "✓ MATCH" if plaintext == decrypted else "✗ MISMATCH"
    print(f"  Result             : {match}")
    print(f"{'='*50}\n")

    # --- Avalanche Effect ---
    print("  Running Avalanche Effect Test...")
    avalanche_test(key, num_rounds)


if __name__ == "__main__":
    main()
