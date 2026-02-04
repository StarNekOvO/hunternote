#!/usr/bin/env python3
"""
CTF Config Generator for StarNeko's whoami challenge

Usage:
    python gen-config.py --key "YOUR_SECRET_KEY" --contact "QQ 123456789"
    
This will output the config values to paste into config.json
"""

import argparse
import hashlib
import base64

def xor_encrypt(data: str, key: str) -> str:
    """Simple XOR encryption, then base64 encode"""
    key_bytes = key.encode()
    data_bytes = data.encode()
    encrypted = bytes([data_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data_bytes))])
    return base64.b64encode(encrypted).decode()

def xor_decrypt(encrypted_b64: str, key: str) -> str:
    """Base64 decode, then XOR decrypt"""
    key_bytes = key.encode()
    encrypted = base64.b64decode(encrypted_b64)
    decrypted = bytes([encrypted[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(encrypted))])
    return decrypted.decode()

def sha256_hash(data: str) -> str:
    """SHA256 hash"""
    return hashlib.sha256(data.encode()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description='Generate CTF config')
    parser.add_argument('--key', required=True, help='The secret key (will be in the binary)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--contact', help='Contact string to encrypt (e.g., "QQ 123456789" or "Telegram @name")')
    group.add_argument('--qq', help='QQ number to encrypt (legacy shortcut; encrypts "QQ <number>")')
    parser.add_argument('--verify', action='store_true', help='Verify decryption works')
    args = parser.parse_args()

    contact_text = args.contact if args.contact is not None else f"QQ {args.qq}"
    
    key_hash = sha256_hash(args.key)
    encrypted_flag = xor_encrypt(contact_text, args.key)
    
    print("\n" + "="*50)
    print("CTF Config Generator")
    print("="*50)
    print(f"\nKey: {args.key}")
    print(f"Contact: {contact_text}")
    print("\n--- Copy these to config.json ---\n")
    print(f'"keyHash": "{key_hash}",')
    print(f'"encryptedFlag": "{encrypted_flag}"')
    
    if args.verify:
        decrypted = xor_decrypt(encrypted_flag, args.key)
        print(f"\n--- Verification ---")
        print(f"Decrypted: {decrypted}")
        print(f"Match: {decrypted == contact_text}")
    
    print("\n--- Compile command ---\n")
    print(f'gcc -DKEY=\'"{args.key}"\' -fno-stack-protector -no-pie -o re_checkin re_checkin.c')
    print()

if __name__ == '__main__':
    main()
