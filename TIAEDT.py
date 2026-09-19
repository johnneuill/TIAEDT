# =============================================================================
# TOTALLY INDEPENDANT AES ENCRYPT / DECRYPT TOOL : TIAEDT
# =============================================================================
#
# Description:
#   Simple AES-256-CBC encryption/decryption utility.
#
# Features:
#   - AES-256-CBC encryption
#   - AES-256-CBC decryption
#   - PKCS#7 padding
#   - Base64 output for easy transport/storage
#   - Command-line interface
#
# Requirements:
#   pip install pycryptodome
#
# Usage:
#   Encrypt:
#       python TIAEDT.py encrypt "Hello World"
#
#   Decrypt:
#       python TIAEDT.py decrypt "<BASE64_CIPHERTEXT>"
#
# Notes:
#   - AES-256 requires a 32-byte key.
#   - AES-CBC requires a 16-byte IV.
#
# =============================================================================

import sys
import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# -----------------------------------------------------------------------------
# AES ENCRYPTION
# -----------------------------------------------------------------------------

def encrypt(plaintext: str, key: bytes, iv: bytes) -> str:
    """
    Encrypt plaintext using AES-256-CBC.

    Returns:
        Base64-encoded ciphertext.
    """

    plaintext_bytes = plaintext.encode("utf-8")

    # PKCS#7 padding to AES block size (128 bits)
    padded_data = pad(plaintext_bytes, AES.block_size)

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )

    ciphertext = cipher.encrypt(padded_data)

    return base64.b64encode(ciphertext).decode("utf-8")


# -----------------------------------------------------------------------------
# AES DECRYPTION
# -----------------------------------------------------------------------------

def decrypt(ciphertext_b64: str, key: bytes, iv: bytes) -> str:
    """
    Decrypt Base64-encoded AES ciphertext.

    Returns:
        Decrypted UTF-8 plaintext.
    """

    try:
        ciphertext = base64.b64decode(ciphertext_b64)

        cipher = AES.new(
            key,
            AES.MODE_CBC,
            iv
        )

        padded_data = cipher.decrypt(ciphertext)

        # Remove PKCS#7 padding
        plaintext_bytes = unpad(
            padded_data,
            AES.block_size
        )

        return plaintext_bytes.decode("utf-8")

    except Exception as exc:
        raise ValueError(
            "Invalid ciphertext or incorrect encryption parameters."
        ) from exc


# -----------------------------------------------------------------------------
# INPUT VALIDATION
# -----------------------------------------------------------------------------

def get_key_and_iv():
    """
    Ask the user for the AES key and IV.
    """

    key = input("Enter AES-256 Key (32 bytes): ").encode("utf-8")
    iv = input("Enter IV (16 bytes): ").encode("utf-8")

    if len(key) != 32:
        print("Error: AES-256 key must be exactly 32 bytes.")
        sys.exit(1)

    if len(iv) != 16:
        print("Error: IV must be exactly 16 bytes.")
        sys.exit(1)

    return key, iv


# -----------------------------------------------------------------------------
# COMMAND-LINE INTERFACE
# -----------------------------------------------------------------------------

def main():
    if len(sys.argv) < 3:
        print('Usage:')
        print()
        print('  Encrypt:')
        print('    python TIAEDT.py encrypt "Hello World"')
        print()
        print('  Decrypt:')
        print('    python TIAEDT.py decrypt "<BASE64_CIPHERTEXT>"')
        sys.exit(1)

    operation = sys.argv[1].lower()
    value = sys.argv[2]

    # Get Key and IV from user
    key, iv = get_key_and_iv()

    if operation == "encrypt":
        result = encrypt(value, key, iv)
        print(result)

    elif operation == "decrypt":
        try:
            result = decrypt(value, key, iv)
            print(result)

        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

    else:
        print(
            f"Error: Unknown operation '{operation}'",
            file=sys.stderr
        )
        print(
            "Valid operations: encrypt, decrypt",
            file=sys.stderr
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
