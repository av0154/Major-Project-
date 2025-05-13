from crypto_utils import encrypt_message, decrypt_message

msg = "AUTH_KASHYAPA"
encrypted_msg = encrypt_message(msg)
print(f"Encrypted message: {encrypted_msg}")

decrypted_msg = decrypt_message(encrypted_msg)
print(f"Decrypted message: {decrypted_msg}")

