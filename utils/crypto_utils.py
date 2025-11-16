"""
Cryptographic Utilities Module - Provides core cryptographic operations for secure chat.

Features:
- RSA signing and verification (RSASSA-PSS with SHA-256)
- AES-128-CBC encryption/decryption with PKCS#7 padding
- SHA-256 hashing
- Certificate validation and fingerprinting
- Big-endian serialization (8-byte integers)
- Constant-time comparison for security-critical values

CIANR Mapping:
- Confidentiality: AES-128-CBC encryption
- Integrity: SHA-256 hashing, RSA signatures
- Authenticity: RSA signatures, certificate chain validation
- Non-Repudiation: RSA signatures with timestamps
"""

import os
import struct
import base64
import hashlib
from typing import Tuple, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID


# ============================================================================
# RSA Signing and Verification
# ============================================================================


def rsa_sign(private_key_pem: bytes, data: bytes) -> bytes:
    """
    Sign data with RSA private key using RSASSA-PSS with SHA-256.

    Args:
        private_key_pem: Private key in PEM format
        data: Data to sign

    Returns:
        Binary signature

    CIANR: Non-Repudiation + Integrity
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    return signature


def rsa_verify(public_key_pem: bytes, data: bytes, signature: bytes) -> bool:
    """
    Verify RSA signature with public key using RSASSA-PSS with SHA-256.

    Args:
        public_key_pem: Public key in PEM format (or cert PEM)
        data: Original data
        signature: Signature to verify

    Returns:
        True if signature is valid, False otherwise

    CIANR: Authenticity + Integrity
    """
    try:
        # Try loading as certificate first
        try:
            cert = x509.load_pem_x509_certificate(public_key_pem, default_backend())
            public_key = cert.public_key()
        except Exception:
            # Fall back to loading as public key
            public_key = serialization.load_pem_public_key(
                public_key_pem, backend=default_backend()
            )

        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# ============================================================================
# AES-128-CBC Encryption and Decryption
# ============================================================================


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext with AES-128-CBC and PKCS#7 padding.

    Args:
        key: 16-byte AES key
        plaintext: Data to encrypt

    Returns:
        IV (16 bytes) + ciphertext (variable), not base64 encoded

    CIANR: Confidentiality
    """
    if len(key) != 16:
        raise ValueError(f"AES key must be 16 bytes, got {len(key)}")

    # Generate random IV
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # PKCS#7 padding
    plaintext_len = len(plaintext)
    padding_len = 16 - (plaintext_len % 16)
    padded_plaintext = plaintext + bytes([padding_len]) * padding_len

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Return IV concatenated with ciphertext
    return iv + ciphertext


def aes_decrypt(key: bytes, ciphertext_with_iv: bytes) -> bytes:
    """
    Decrypt ciphertext from AES-128-CBC with PKCS#7 padding.

    Args:
        key: 16-byte AES key
        ciphertext_with_iv: IV (16 bytes) + ciphertext

    Returns:
        Decrypted plaintext

    CIANR: Confidentiality

    Raises:
        ValueError: If decryption fails or padding is invalid
    """
    if len(key) != 16:
        raise ValueError(f"AES key must be 16 bytes, got {len(key)}")

    if len(ciphertext_with_iv) < 16:
        raise ValueError("Ciphertext must contain at least IV (16 bytes)")

    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]

    if len(ciphertext) == 0:
        raise ValueError("Ciphertext is empty")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS#7 padding
    padding_len = padded_plaintext[-1]
    if padding_len > 16 or padding_len == 0:
        raise ValueError(f"Invalid padding length: {padding_len}")

    plaintext = padded_plaintext[:-padding_len]
    return plaintext


# ============================================================================
# SHA-256 Hashing
# ============================================================================


def sha256_hash(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of data.

    Args:
        data: Data to hash

    Returns:
        32-byte SHA-256 hash

    CIANR: Integrity
    """
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """
    Compute SHA-256 hash and return as hex string.

    Args:
        data: Data to hash

    Returns:
        Hex string (64 characters)

    CIANR: Integrity
    """
    return hashlib.sha256(data).hexdigest()


# ============================================================================
# Big-Endian Serialization
# ============================================================================


def int_to_bytes_be(value: int, length: int = 8) -> bytes:
    """
    Convert integer to big-endian bytes.

    Args:
        value: Integer to convert
        length: Byte length (default 8 for 64-bit)

    Returns:
        Big-endian byte representation

    Usage:
        - seqno (64-bit): int_to_bytes_be(seqno, 8)
        - timestamp (64-bit): int_to_bytes_be(ts, 8)
    """
    return value.to_bytes(length, byteorder="big")


def bytes_to_int_be(data: bytes) -> int:
    """
    Convert big-endian bytes to integer.

    Args:
        data: Big-endian byte data

    Returns:
        Integer value
    """
    return int.from_bytes(data, byteorder="big")


# ============================================================================
# Certificate Operations
# ============================================================================


def cert_fingerprint(cert_pem: bytes) -> str:
    """
    Compute SHA-256 fingerprint of certificate in DER format.

    Args:
        cert_pem: Certificate in PEM format

    Returns:
        Hex string of SHA-256(DER)

    CIANR: Authenticity (identifies certificate)
    """
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    der_data = cert.public_bytes(serialization.Encoding.DER)
    return sha256_hex(der_data)


def load_certificate(cert_pem: bytes) -> x509.Certificate:
    """Load certificate from PEM bytes."""
    return x509.load_pem_x509_certificate(cert_pem, default_backend())


def get_certificate_cn(cert: x509.Certificate) -> Optional[str]:
    """Extract Common Name (CN) from certificate subject."""
    try:
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                return attr.value
    except Exception:
        pass
    return None


def validate_certificate_chain(
    cert_pem: bytes, ca_cert_pem: bytes, allow_self_signed: bool = False
) -> Tuple[bool, str]:
    """
    Validate certificate signature chain against CA certificate.

    Args:
        cert_pem: Certificate to validate (PEM)
        ca_cert_pem: CA certificate (PEM)
        allow_self_signed: If True, allow self-signed certificates

    Returns:
        (is_valid, reason_if_invalid)

    Validation checks:
        1. Certificate not yet valid (notBefore)
        2. Certificate expired (notAfter)
        3. Signature chain to CA
        4. Self-signed check (if needed)

    CIANR: Authenticity
    """
    try:
        cert = load_certificate(cert_pem)
        ca_cert = load_certificate(ca_cert_pem)

        # Check validity period
        from datetime import datetime

        now = datetime.utcnow()
        if now < cert.not_valid_before:
            return False, f"Certificate not yet valid (notBefore: {cert.not_valid_before})"

        if now > cert.not_valid_after:
            return False, f"Certificate expired (notAfter: {cert.not_valid_after})"

        # Verify signature against CA
        ca_public_key = ca_cert.public_key()
        try:
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except Exception as e:
            return False, f"Signature verification failed: {str(e)}"

        return True, "Certificate valid"

    except Exception as e:
        return False, f"Certificate validation error: {str(e)}"


# ============================================================================
# Constant-Time Comparison
# ============================================================================


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time to prevent timing attacks.

    Args:
        a: First byte string
        b: Second byte string

    Returns:
        True if equal, False otherwise

    CIANR: Authenticity (prevent timing attacks on authentication)
    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= x ^ y

    return result == 0


# ============================================================================
# Key Extraction from Private Key Files
# ============================================================================


def load_private_key(key_pem: bytes) -> rsa.RSAPrivateKey:
    """Load RSA private key from PEM bytes."""
    return serialization.load_pem_private_key(
        key_pem, password=None, backend=default_backend()
    )


def load_public_key(key_pem: bytes):
    """Load RSA public key from PEM bytes."""
    return serialization.load_pem_public_key(key_pem, backend=default_backend())


def get_public_key_pem(private_key_pem: bytes) -> bytes:
    """Extract public key from private key."""
    private_key = load_private_key(private_key_pem)
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
