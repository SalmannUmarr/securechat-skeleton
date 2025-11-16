#!/usr/bin/env python3
"""
CA Generation Script - Generates a self-signed Root CA certificate for the secure chat system.

This script creates:
- ca_private_key.pem: Private key for the CA (RSA 2048, NOT committed)
- ca_cert.pem: Self-signed CA certificate (public, committed)

Usage:
    python scripts/gen_ca.py

The CA certificate is used to sign client and server certificates for mutual authentication.
"""

import os
import sys
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


def generate_ca_certificate(
    cert_dir: str = "certs",
    ca_key_file: str = "ca_private_key.pem",
    ca_cert_file: str = "ca_cert.pem",
    key_size: int = 2048,
    validity_days: int = 3650,
):
    """
    Generate a self-signed Root CA certificate with RSA 2048-bit key.

    Args:
        cert_dir: Directory to store certificates
        ca_key_file: Filename for private key (NOT committed)
        ca_cert_file: Filename for public certificate
        key_size: RSA key size (minimum 2048)
        validity_days: Certificate validity period in days

    CIANR Property: Authenticity - Root CA enables all subsequent certificate validation.
    """
    # Ensure cert directory exists
    os.makedirs(cert_dir, exist_ok=True)

    ca_key_path = os.path.join(cert_dir, ca_key_file)
    ca_cert_path = os.path.join(cert_dir, ca_cert_file)

    # Check if CA already exists
    if os.path.exists(ca_cert_path):
        print(f"[!] CA certificate already exists at {ca_cert_path}")
        response = input("Overwrite? (y/n): ")
        if response.lower() != "y":
            print("Aborting.")
            return False

    print("[*] Generating CA RSA private key (2048-bit)...")
    from cryptography.hazmat.primitives.asymmetric import rsa

    ca_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )

    print("[*] Creating self-signed CA certificate...")
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Chat Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Secure Chat Root CA"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256(), backend=default_backend())
    )

    # Write private key (NOT committed to version control)
    print(f"[*] Writing CA private key to {ca_key_path} (keep secure)...")
    with open(ca_key_path, "wb") as f:
        f.write(
            ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.chmod(ca_key_path, 0o600)  # Restrict access to owner only

    # Write certificate (public, OK to commit)
    print(f"[*] Writing CA certificate to {ca_cert_path}...")
    with open(ca_cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("\n[+] CA Certificate successfully generated!")
    print(f"    CA Key:  {ca_key_path} (PRIVATE - not committed)")
    print(f"    CA Cert: {ca_cert_path} (PUBLIC - committed)")
    print(f"\n    Subject: {cert.subject.rfc4514_string()}")
    print(f"    Valid: {cert.not_valid_before} to {cert.not_valid_after}")
    print(f"    Serial: {cert.serial_number}")

    return True


if __name__ == "__main__":
    success = generate_ca_certificate()
    sys.exit(0 if success else 1)
