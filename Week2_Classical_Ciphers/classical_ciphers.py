def caesar_cipher(text, shift, mode="encrypt"):
    result = ""
    if mode == "decrypt":
        shift = -shift
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result


def vigenere_cipher(text, key, mode="encrypt"):
    result = ""
    key = key.upper()
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord("A")
            if mode == "decrypt":
                shift = -shift
            base = ord("A") if char.isupper() else ord("a")
            result += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result


def validate_input(text, key=None):
    if not text.strip():
        return False, "Error: Message cannot be empty."
    if key is not None and not key.isalpha():
        return False, "Error: Key must contain letters only."
    return True, "Valid input."


print("=" * 40)
print("        CAESAR CIPHER")
print("=" * 40)
message = "SecureLoginSystem"
shift = 3
encrypted = caesar_cipher(message, shift)
decrypted = caesar_cipher(encrypted, shift, mode="decrypt")
print(f"Original:  {message}")
print(f"Shift:     {shift}")
print(f"Encrypted: {encrypted}")
print(f"Decrypted: {decrypted}")


print("\n" + "=" * 40)
print("        VIGENÈRE CIPHER")
print("=" * 40)
message2 = "HelloFlaskWorld"
key = "CRYPTO"
enc2 = vigenere_cipher(message2, key)
dec2 = vigenere_cipher(enc2, key, mode="decrypt")
print(f"Original:  {message2}")
print(f"Key:       {key}")
print(f"Encrypted: {enc2}")
print(f"Decrypted: {dec2}")


print("\n" + "=" * 40)
print("        INPUT VALIDATION")
print("=" * 40)
tests = [("", "CRYPTO"), ("Hello", "123"), ("Hello", "CRYPTO")]
for msg, k in tests:
    valid, response = validate_input(msg, k)
    print(f"Message: '{msg}' | Key: '{k}' → {response}")


print("\n" + "=" * 40)
print("        SECURITY COMPARISON")
print("=" * 40)
print("Caesar Cipher  → Single shift key, vulnerable to brute force (26 possibilities)")
print("Vigenère Cipher → Polyalphabetic, significantly harder to crack")
