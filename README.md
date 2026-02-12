# FritzDecrypt

A Python tool to decrypt passwords and credentials from Fritz!Box configuration export files.

## Features

- Decrypts DSL/PPPoE credentials, VoIP passwords, and other secrets from Fritz!Box backup files
- Works with Fritz!OS 8.x (tested with 8.20)
- Uses the `cryptography` library for Python 3.10+ compatibility

## Installation

```bash
pip install cryptography
```

## Usage

```bash
python3 fritzdecrypt.py <export_file> <password>
```

**Example:**
```bash
python3 fritzdecrypt.py backup.export mypassword
```

**Output:**
```
Export file: backup.export
Password: mypassword

Encryption key: 001d589f60ddcaf7e560c0cf12ab8ca3

==================================================
Decrypted credentials:
==================================================
  username: 001234567890#520012345678#0001@t-online.de
  passwd: 12345678
  ...
```

## How It Works

Fritz!Box uses a **two-stage AES-256-CBC encryption** system to protect sensitive data in export files.

### Encryption Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         STAGE 1: KEY DERIVATION                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Export Password ──► MD5 Hash ──► Pad with 16 zeros ──► Bootstrap Key      │
│     "1234"           (16 bytes)      (+16 bytes)          (32 bytes)        │
│                                                                             │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    STAGE 2: DECRYPT ENCRYPTION KEY                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Password=$$$$WZEHYGG6KL...                                                │
│            │                                                                │
│            ▼                                                                │
│   Base32 Decode (AVM alphabet: A-Z1-6)                                      │
│            │                                                                │
│            ▼                                                                │
│   ┌────────────────┬─────────────────┐                                      │
│   │  IV (16 bytes) │   Ciphertext    │                                      │
│   └────────────────┴────────┬────────┘                                      │
│                             │                                               │
│                             ▼                                               │
│              AES-256-CBC Decrypt ◄── Bootstrap Key                          │
│                             │                                               │
│                             ▼                                               │
│                    Encryption Key (16 bytes + 16 zeros)                     │
│                                                                             │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       STAGE 3: DECRYPT SECRETS                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   username="$$$$4UPSGITM..."                                                │
│            │                                                                │
│            ▼                                                                │
│   Base32 Decode ──► IV + Ciphertext                                         │
│                             │                                               │
│                             ▼                                               │
│              AES-256-CBC Decrypt ◄── Encryption Key                         │
│                             │                                               │
│                             ▼                                               │
│              "001234567890#...@t-online.de"                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Decrypted Data Structure

After AES decryption, the plaintext has this structure:

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 4 bytes | MD5 hash prefix (for validation) |
| 4 | 4 bytes | Data length (big-endian) |
| 8 | variable | Actual data (null-terminated if string) |

### Key Details

- **Base32 Alphabet**: Fritz!Box uses a custom alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZ123456` (not standard Base32)
- **Bootstrap Key**: `MD5(password) + 16 zero bytes` = 32 bytes for AES-256
- **IV**: First 16 bytes of each encrypted blob (random per value)
- **Encryption Key**: Only first 16 bytes are used, upper 16 bytes are zeros

## Why Two-Stage Encryption?

1. **Security**: The actual encryption key is randomly generated (high entropy)
2. **Flexibility**: Without a password, Fritz!Box can derive the bootstrap key from device properties (serial number + MAC address)
3. **Strength**: A random key is cryptographically stronger than a user-chosen password

## Credits & References

This tool is based on research and code from:

- **[PeterPawn/decoder](https://github.com/PeterPawn/decoder)** - Original shell scripts for Fritz!Box decryption
- **[xiretza/fritzdecode](https://gitlab.com/xiretza/fritzdecode)** - Rust implementation with the key derivation algorithm

## License

MIT License
