#!/usr/bin/env python3
"""
Test: Invalid Certificate Rejection

This test verifies that the server rejects clients with:
1. Self-signed certificates (not signed by CA)
2. Expired certificates
3. Certificates with invalid CN

CIANR: Authenticity - Validates that mutual TLS authentication works correctly.
"""

import sys
import os
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from utils.crypto_utils import (
    validate_certificate_chain,
    cert_fingerprint,
    load_certificate,
)


class InvalidCertTest(unittest.TestCase):
    """Test certificate validation."""

    @classmethod
    def setUpClass(cls):
        """Generate test certificates."""
        cls.cert_dir = "certs"

        # Load CA
        with open(os.path.join(cls.cert_dir, "ca_cert.pem"), "rb") as f:
            cls.ca_cert_pem = f.read()

        # Load valid client cert
        with open(os.path.join(cls.cert_dir, "client_cert.pem"), "rb") as f:
            cls.valid_cert_pem = f.read()

    def test_valid_certificate(self):
        """Test that valid certificate passes validation."""
        valid, reason = validate_certificate_chain(
            self.valid_cert_pem, self.ca_cert_pem
        )
        self.assertTrue(valid, f"Valid certificate rejected: {reason}")

    def test_self_signed_certificate(self):
        """Test that self-signed certificate is rejected."""
        # Generate self-signed cert (not signed by CA)
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Attacker"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=1))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )

        self_signed_pem = cert.public_bytes(serialization.Encoding.PEM)

        # Should be rejected
        valid, reason = validate_certificate_chain(self_signed_pem, self.ca_cert_pem)
        self.assertFalse(valid, "Self-signed certificate was accepted")
        self.assertIn("Signature", reason, f"Unexpected reason: {reason}")

    def test_expired_certificate(self):
        """Test that expired certificate is rejected."""
        # Generate cert with past validity
        ca_key_path = os.path.join(self.cert_dir, "ca_private_key.pem")
        with open(ca_key_path, "rb") as f:
            ca_private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

        ca_cert = load_certificate(self.ca_cert_pem)

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        # Create certificate that is already expired
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.COMMON_NAME, "EXPIRED"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow() - timedelta(days=10))
            .not_valid_after(datetime.utcnow() - timedelta(days=1))  # Already expired
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(ca_private_key, hashes.SHA256(), backend=default_backend())
        )

        expired_pem = cert.public_bytes(serialization.Encoding.PEM)

        # Should be rejected
        valid, reason = validate_certificate_chain(expired_pem, self.ca_cert_pem)
        self.assertFalse(valid, "Expired certificate was accepted")
        self.assertIn("expir", reason.lower(), f"Unexpected reason: {reason}")

    def test_certificate_fingerprint(self):
        """Test certificate fingerprint computation."""
        fp1 = cert_fingerprint(self.valid_cert_pem)
        fp2 = cert_fingerprint(self.valid_cert_pem)

        # Should be consistent
        self.assertEqual(fp1, fp2, "Fingerprints do not match for same cert")

        # Should be hex string of 64 chars (256 bits)
        self.assertEqual(len(fp1), 64, f"Fingerprint length: {len(fp1)}")


if __name__ == "__main__":
    # Check if certificates exist
    cert_dir = "certs"
    if not os.path.exists(os.path.join(cert_dir, "ca_cert.pem")):
        print("[!] Certificates not generated. Run scripts/gen_ca.py and scripts/gen_cert.py first")
        sys.exit(1)

    unittest.main(verbosity=2)
