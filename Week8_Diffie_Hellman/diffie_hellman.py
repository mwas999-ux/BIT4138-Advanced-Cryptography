# ============================================
# BIT4138 - Advanced Cryptography
# Week 8 Practical: Diffie-Hellman Key Exchange
# Name: Mwangi
# Reg: BSCCS/2024/74352
# ============================================

def generate_public_key(g, private_key, p):
    """Compute public key: g^private mod p"""
    return pow(g, private_key, p)

def generate_shared_secret(other_public, private_key, p):
    """Compute shared secret: other_public^private mod p"""
    return pow(other_public, private_key, p)

def main():
    print("=" * 45)
    print("   Diffie-Hellman Key Exchange Protocol")
    print("=" * 45)

    p = int(input("\nEnter public prime (p): "))
    g = int(input("Enter generator (g): "))

    print("\n--- Private Keys (kept secret) ---")
    alice_private = int(input("Alice's private key: "))
    bob_private   = int(input("Bob's private key: "))

    alice_public = generate_public_key(g, alice_private, p)
    bob_public   = generate_public_key(g, bob_private, p)

    print("\n--- Public Keys (shared openly) ---")
    print(f"Alice's Public Key: {alice_public}")
    print(f"Bob's Public Key:   {bob_public}")

    alice_secret = generate_shared_secret(bob_public, alice_private, p)
    bob_secret   = generate_shared_secret(alice_public, bob_private, p)

    print("\n--- Shared Secrets ---")
    print(f"Alice computed: {alice_secret}")
    print(f"Bob computed:   {bob_secret}")

    print("\n--- Verification ---")
    if alice_secret == bob_secret:
        print(f"✅ Shared secret established: {alice_secret}")
        print("Both parties have the same key. Secure channel ready.")
    else:
        print("❌ Mismatch! Something went wrong.")

main()
