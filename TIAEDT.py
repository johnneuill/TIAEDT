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
#   - Predefined constant Key and IV
#   - Base64 output for easy transport/storage
#   - Command-line interface
#
# Requirements:
#   pip install pycryptodome
#
# Usage:
#   Encrypt:
#       python aes_tool.py encrypt "Hello World"
#
#   Decrypt:
#       python aes_tool.py decrypt "<BASE64_CIPHERTEXT>"
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
# CONSTANT KEY AND IV
# -----------------------------------------------------------------------------

# 32 bytes = AES-256
KEY = b"86b50a3d066819458bf2a8cbfefefb22"

# 16 bytes = AES block size
IV = b"c57e764b2deb8593"


# -----------------------------------------------------------------------------
# AES ENCRYPTION
# -----------------------------------------------------------------------------

def encrypt(plaintext: str) -> str:
    """
    Encrypt plaintext using AES-256-CBC.

    Returns:
        Base64-encoded ciphertext.
    """

    plaintext_bytes = plaintext.encode("utf-8")

    # PKCS#7 padding to AES block size (128 bits)
    padded_data = pad(plaintext_bytes, AES.block_size)

    cipher = AES.new(
        KEY,
        AES.MODE_CBC,
        IV
    )

    ciphertext = cipher.encrypt(padded_data)

    return base64.b64encode(ciphertext).decode("utf-8")


# -----------------------------------------------------------------------------
# AES DECRYPTION
# -----------------------------------------------------------------------------

def decrypt(ciphertext_b64: str) -> str:
    """
    Decrypt Base64-encoded AES ciphertext.

    Returns:
        Decrypted UTF-8 plaintext.
    """

    try:
        ciphertext = base64.b64decode(ciphertext_b64)

        cipher = AES.new(
            KEY,
            AES.MODE_CBC,
            IV
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
# COMMAND-LINE INTERFACE
# -----------------------------------------------------------------------------

def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print()
        print("  Encrypt:")
        print('    python TIAEDT.py encrypt "Hello World"')
        print()
        print("  Decrypt:")
        print('    python TIAEDT.py decrypt "<BASE64_CIPHERTEXT>"')
        sys.exit(1)

    operation = sys.argv[1].lower()
    value = sys.argv[2]

    if operation == "encrypt":
        result = encrypt(value)
        print(result)

    elif operation == "decrypt":
        try:
            result = decrypt(value)
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