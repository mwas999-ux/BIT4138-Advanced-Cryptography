from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)

message = b"Secure Login System - Week 1 Test"
encrypted = cipher.encrypt(message)
decrypted = cipher.decrypt(encrypted)

print(f"Original Message: {message}")
print(f"Encrypted Message: {encrypted}")
print(f"Decrypted Message: {decrypted}")
