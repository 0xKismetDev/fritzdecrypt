#!/usr/bin/env python3
"""
Fritz!Box Export File Decryptor
Decrypts passwords from Fritz!Box configuration export files.
Based on fritzdecode algorithm.

Usage: python3 fritzbox_decrypt.py <export_file> <password>
"""

import hashlib
import struct
import sys
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Fritz!Box uses a custom Base32 alphabet
FRITZBOX_BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"


def fritzbox_base32_decode(encoded):
    """Decode Fritz!Box custom Base32 encoding"""
    result = bytearray()

    # Process in chunks of 8 characters = 40 bits = 5 bytes
    i = 0
    while i < len(encoded):
        chunk = encoded[i:i+8]
        if len(chunk) < 8:
            chunk = chunk + 'A' * (8 - len(chunk))

        value = 0
        for c in chunk:
            idx = FRITZBOX_BASE32.index(c)
            value = (value << 5) | idx

        # Extract 5 bytes from 40 bits
        for j in range(4, -1, -1):
            result.append((value >> (j * 8)) & 0xFF)

        i += 8

    return bytes(result)


def generate_bootstrap_key(password):
    """Generate 32-byte bootstrap key from password (MD5 + 16 zero bytes)"""
    md5_hash = hashlib.md5(password.encode('utf-8')).digest()
    return md5_hash + (b'\x00' * 16)


def aes_decrypt(ciphertext, key, iv):
    """Decrypt using AES-256-CBC"""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def decode_secret(encrypted_base32, key_32bytes, is_string=True):
    """
    Decode a Fritz!Box encrypted secret.

    Format after base32 decode:
    - First 16 bytes: IV
    - Rest: Ciphertext

    After AES decryption:
    - 4 bytes: MD5 hash prefix
    - 4 bytes: Length (big-endian)
    - Rest: Data (padded to 16 bytes)
    """
    # Decode base32
    encrypted_bytes = fritzbox_base32_decode(encrypted_base32)

    # Extract IV (first 16 bytes) and ciphertext
    if len(encrypted_bytes) < 32:
        raise ValueError(f"Encrypted data too short: {len(encrypted_bytes)} bytes")

    iv = encrypted_bytes[:16]
    ciphertext = encrypted_bytes[16:]

    # Ensure ciphertext is multiple of 16 bytes
    if len(ciphertext) % 16 != 0:
        ciphertext = ciphertext[:len(ciphertext) - (len(ciphertext) % 16)]

    if len(ciphertext) == 0:
        raise ValueError("No ciphertext after IV extraction")

    # Decrypt with AES-256-CBC
    decrypted = aes_decrypt(ciphertext, key_32bytes, iv)

    # Parse decrypted data
    if len(decrypted) < 8:
        raise ValueError(f"Decrypted data too short: {len(decrypted)} bytes")

    stored_hash = decrypted[:4]
    length = struct.unpack('>I', decrypted[4:8])[0]
    data = decrypted[8:]

    # Extract actual data based on length
    if length > len(data):
        result = data.rstrip(b'\x00')
    else:
        result = data[:length]

    # Remove null terminator if string
    if is_string and result.endswith(b'\x00'):
        result = result[:-1]

    return result


def decrypt_encryption_key(encrypted_key_base32, bootstrap_key):
    """Decrypt the encryption key from the Password header field"""
    decrypted = decode_secret(encrypted_key_base32, bootstrap_key, is_string=False)

    # The encryption key is 32 bytes, but only first 16 are used
    key = bytearray(decrypted[:32] if len(decrypted) >= 32 else decrypted + b'\x00' * (32 - len(decrypted)))
    # Zero out upper half
    for i in range(16, 32):
        key[i] = 0

    return bytes(key)


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 fritzbox_decrypt.py <export_file> <password>")
        print("Example: python3 fritzbox_decrypt.py backup.export 1234")
        sys.exit(1)

    export_file = sys.argv[1]
    export_password = sys.argv[2]

    print(f"Export file: {export_file}")
    print(f"Password: {export_password}")

    with open(export_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Find the Password field in header
    password_match = re.search(r'^Password=\$\$\$\$(.+)$', content, re.MULTILINE)
    if not password_match:
        print("ERROR: No encrypted password field found in header")
        sys.exit(1)

    encrypted_key = password_match.group(1).strip()

    # Generate bootstrap key
    bootstrap_key = generate_bootstrap_key(export_password)

    # Decrypt the encryption key
    try:
        encryption_key = decrypt_encryption_key(encrypted_key, bootstrap_key)
    except Exception as e:
        print(f"ERROR: Failed to decrypt - wrong password? ({e})")
        sys.exit(1)

    print(f"\nEncryption key: {encryption_key[:16].hex()}")
    print("\n" + "="*50)
    print("Decrypted credentials:")
    print("="*50)

    # Find and decrypt all username/passwd fields
    encrypted_values = re.findall(r'(\w+)\s*=\s*"\$\$\$\$([A-Z0-9]+)"', content)

    seen = set()
    for name, value in encrypted_values:
        if name in ['username', 'passwd', 'password', 'authname']:
            try:
                decrypted = decode_secret(value, encryption_key)
                decoded = decrypted.decode('utf-8', errors='replace').strip('\x00')
                if decoded and len(decoded) > 1:
                    key = f"{name}:{decoded}"
                    if key not in seen:
                        seen.add(key)
                        print(f"  {name}: {decoded}")
            except:
                pass


if __name__ == "__main__":
    main()
