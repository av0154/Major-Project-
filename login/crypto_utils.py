from Crypto.Cipher import AES
import base64


key = b'SECUREKASHYAPA12' 

def pad(s):
    padding = 16 - len(s) % 16
    return s + (chr(padding) * padding)

def unpad(s):
    if isinstance(s, bytes):
        padding_length = s[-1]  
        return s[:-padding_length]  
    else:
        raise ValueError("Input must be a byte object")

def encrypt_message(msg):
    cipher = AES.new(key, AES.MODE_ECB)  
    encrypted = cipher.encrypt(pad(msg).encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_message(enc_msg):
    cipher = AES.new(key, AES.MODE_ECB)  
    decoded = base64.b64decode(enc_msg)
    decrypted = cipher.decrypt(decoded)
    
    try:
        decrypted_str = unpad(decrypted).decode('utf-8')  
        print(f"Decrypted message: {decrypted_str}")  
        
        if decrypted_str == "AUTH_KASHYAPA":  
            return decrypted_str
        else:
            return "Invalid authentication message"
    except Exception as e:
        print(f"Decryption failed with error: {str(e)}")
        return "Decryption failed"


print(f"Receiver Key: {key}")

