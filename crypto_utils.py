import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derives a 32-byte (256-bit) key from a password and salt using PBKDF2HMAC.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=210000,
    )
    return kdf.derive(password)

def encrypt_file_data(data: bytes, password: str) -> bytes:
    """
    Encrypts data using AES-256 in GCM mode.
    Returns: [16-byte salt][12-byte nonce][ciphertext + 16-byte tag]
    """
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password.encode('utf-8'), salt)
    
    aesgcm = AESGCM(key)
    # The encrypt method outputs the ciphertext with the 16-byte auth tag appended
    ciphertext = aesgcm.encrypt(nonce, data, None)
    
    # Store complete payload
    return salt + nonce + ciphertext

def decrypt_file_data(data: bytes, password: str) -> bytes:
    """
    Decrypts AES-GCM encrypted data.
    Expects data format: [16-byte salt][12-byte nonce][ciphertext + 16-byte tag]
    """
    # Minimum length is salt (16) + nonce (12) + tag (16)
    if len(data) < 44:
        raise ValueError("Invalid file format or corrupted data.")
        
    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]
    
    key = derive_key(password.encode('utf-8'), salt)
    aesgcm = AESGCM(key)
    
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except InvalidTag:
        raise ValueError("Invalid password or corrupted data.")
