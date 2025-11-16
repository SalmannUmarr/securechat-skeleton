#!/usr/bin/env python3
"""
Certificate Issuance Script - Issues client and server certificates signed by the Root CA.

This script creates:
- client_private_key.pem: Client private key (RSA 2048, NOT committed)
- client_cert.pem: Client certificate signed by CA (public)
- server_private_key.pem: Server private key (RSA 2048, NOT committed)
- server_cert.pem: Server certificate signed by CA (public)

Usage:
    python scripts/gen_cert.py client <hostname>
    python scripts/gen_cert.py server <hostname>

Example:
    python scripts/gen_cert.py client localhost
    python scripts/gen_cert.py server localhost

CN (Common Name) validation is enforced during handshake for hostname matching.
"""

import os
import sys
import argparse
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


def load_ca_private_key(ca_key_path: str, password=None):
    """Load CA private key from PEM file."""
    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(), password=password, backend=default_backend()
        )
    return ca_private_key


def load_ca_certificate(ca_cert_path: str):
    """Load CA certificate from PEM file."""
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    return ca_cert


def generate_certificate(
    cert_type: str,
    hostname: str,
    cert_dir: str = "certs",
    ca_key_file: str = "ca_private_key.pem",
    ca_cert_file: str = "ca_cert.pem",
    key_size: int = 2048,
    validity_days: int = 365,
):
    """
    Generate a certificate (client or server) signed by the Root CA.

    Args:
        cert_type: "client" or "server"
        hostname: CN for certificate (used for hostname validation)
        cert_dir: Directory containing CA and output files
        ca_key_file: CA private key filename
        ca_cert_file: CA certificate filename
        key_size: RSA key size (minimum 2048)
        validity_days: Certificate validity period

    CIANR Properties:
    - Authenticity: Signed by trusted CA
    - Non-Repudiation: Certificate identifies entity
    """
    if cert_type not in ("client", "server"):
        print(f"[!] Invalid cert_type: {cert_type}. Use 'client' or 'server'.")
        return False

    ca_key_path = os.path.join(cert_dir, ca_key_file)
    ca_cert_path = os.path.join(cert_dir, ca_cert_file)

    # Verify CA exists
    if not os.path.exists(ca_cert_path):
        print(f"[!] CA certificate not found at {ca_cert_path}")
        print("[!] Run scripts/gen_ca.py first.")
        return False

    if not os.path.exists(ca_key_path):
        print(f"[!] CA private key not found at {ca_key_path}")
        return False

    key_file = os.path.join(cert_dir, f"{cert_type}_private_key.pem")
    cert_file = os.path.join(cert_dir, f"{cert_type}_cert.pem")

    # Check if cert already exists
    if os.path.exists(cert_file):
        print(f"[!] Certificate already exists at {cert_file}")
        response = input("Overwrite? (y/n): ")
        if response.lower() != "y":
            print("Aborting.")
            return False

    print(f"[*] Loading CA certificate and key...")
    ca_cert = load_ca_certificate(ca_cert_path)
    ca_private_key = load_ca_private_key(ca_key_path)

    print(f"[*] Generating {cert_type} RSA private key (2048-bit)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )

    print(f"[*] Creating {cert_type} certificate with CN={hostname}...")
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Chat"),
            x509.NameAttribute(
                NameOID.COMMON_NAME, f"{cert_type.upper()}: {hostname}"
            ),
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
    )

    # Add extensions
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    # Add SubjectAltName for hostname validation
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(hostname)]),
        critical=False,
    )

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    )

    # Sign with CA private key
    cert = builder.sign(ca_private_key, hashes.SHA256(), backend=default_backend())

    # Write private key (NOT committed)
    print(f"[*] Writing {cert_type} private key to {key_file} (keep secure)...")
    with open(key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.chmod(key_file, 0o600)

    # Write certificate (public)
    print(f"[*] Writing {cert_type} certificate to {cert_file}...")
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"\n[+] {cert_type.upper()} Certificate successfully generated!")
    print(f"    Key:  {key_file} (PRIVATE - not committed)")
    print(f"    Cert: {cert_file} (PUBLIC - committed)")
    print(f"\n    Subject: {cert.subject.rfc4514_string()}")
    print(f"    CN: {hostname}")
    print(f"    Valid: {cert.not_valid_before} to {cert.not_valid_after}")
    print(f"    Serial: {cert.serial_number}")

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Generate client or server certificate signed by CA"
    )
    parser.add_argument(
        "cert_type",
        choices=["client", "server"],
        help="Certificate type to generate",
    )
    parser.add_argument("hostname", help="Hostname/CN for the certificate")
    parser.add_argument(
        "--cert-dir",
        default="certs",
        help="Directory containing CA and output certificates",
    )
    parser.add_argument("--ca-key", default="ca_private_key.pem", help="CA key filename")
    parser.add_argument(
        "--ca-cert", default="ca_cert.pem", help="CA certificate filename"
    )
    parser.add_argument(
        "--validity-days", type=int, default=365, help="Certificate validity in days"
    )

    args = parser.parse_args()

    success = generate_certificate(
        cert_type=args.cert_type,
        hostname=args.hostname,
        cert_dir=args.cert_dir,
        ca_key_file=args.ca_key,
        ca_cert_file=args.ca_cert,
        validity_days=args.validity_days,
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
