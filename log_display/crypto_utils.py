from Crypto.Cipher import AES
import base64

KEY = b'SECUREKASHYAPA12'  

def pad(s):
    padding = 16 - len(s) % 16
    return s + (chr(padding) * padding)

def unpad(s):
    return s[:-ord(s[-1])]

def encrypt_message(msg):
    cipher = AES.new(KEY, AES.MODE_ECB)  
    encrypted = cipher.encrypt(pad(msg).encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_message(enc_msg):
    cipher = AES.new(KEY, AES.MODE_ECB)  
    decoded = base64.b64decode(enc_msg)
    decrypted = cipher.decrypt(decoded)
    return unpad(decrypted)

if __name__ == "__main__":
    encrypted_message = encrypt_message("AUTH_KASHYAPA")
    print("Encrypted message:", encrypted_message)

print(f"Sender Key: {KEY}")

