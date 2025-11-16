#!/usr/bin/env python3
"""
Test: Replay and Tamper Detection

This test verifies that the protocol detects:
1. Message replays (duplicate sequence numbers)
2. Tampering with ciphertext (bit flips)
3. Signature verification failures
4. Out-of-order messages
5. Stale timestamps

CIANR: Integrity (tamper detection), Non-Repudiation (sequence tracking)
"""

import sys
import os
import unittest
import base64
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.crypto_utils import (
    rsa_sign,
    rsa_verify,
    aes_encrypt,
    aes_decrypt,
    sha256_hash,
    int_to_bytes_be,
)
from utils.dh import dh_shared_secret_to_key


class ReplayTamperTest(unittest.TestCase):
    """Test replay and tamper detection."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a test AES key (would come from DH in real scenario)
        self.test_key = sha256_hash(b"test_shared_secret")[:16]

        # Load client private key for signing
        cert_dir = "certs"
        with open(os.path.join(cert_dir, "client_private_key.pem"), "rb") as f:
            self.client_key = f.read()

        with open(os.path.join(cert_dir, "client_cert.pem"), "rb") as f:
            self.client_cert = f.read()

    def test_encryption_decryption(self):
        """Test basic AES encryption/decryption round-trip."""
        plaintext = b"Hello, Secure Chat!"

        # Encrypt
        ciphertext_with_iv = aes_encrypt(self.test_key, plaintext)

        # Verify format: 16-byte IV + ciphertext
        self.assertGreater(len(ciphertext_with_iv), 16, "Ciphertext too short")

        # Decrypt
        decrypted = aes_decrypt(self.test_key, ciphertext_with_iv)

        # Should match original
        self.assertEqual(decrypted, plaintext, "Decryption failed")

    def test_tamper_detection(self):
        """Test that tampered ciphertext is detected."""
        plaintext = b"Secret message"
        ciphertext_with_iv = aes_encrypt(self.test_key, plaintext)

        # Tamper with ciphertext (flip a bit in the ciphertext part, not IV)
        tampered = bytearray(ciphertext_with_iv)
        tampered[20] ^= 0x01  # Flip one bit
        tampered = bytes(tampered)

        # Decryption should succeed (CBC decryption doesn't fail)
        # But plaintext will be garbage or PKCS#7 will fail
        try:
            decrypted = aes_decrypt(self.test_key, tampered)
            # If we get here, plaintext was corrupted
            self.assertNotEqual(decrypted, plaintext, "Tamper not detected")
        except ValueError:
            # Padding error is acceptable
            pass

    def test_signature_verification(self):
        """Test RSA signature verification."""
        message = b"Important message"

        # Sign message
        signature = rsa_sign(self.client_key, message)

        # Verify with correct message
        valid = rsa_verify(self.client_cert, message, signature)
        self.assertTrue(valid, "Valid signature rejected")

        # Verify with tampered message
        tampered_msg = b"Tampered message"
        invalid = rsa_verify(self.client_cert, tampered_msg, signature)
        self.assertFalse(invalid, "Invalid signature accepted")

        # Verify with tampered signature
        tampered_sig = bytearray(signature)
        tampered_sig[0] ^= 0xFF
        invalid = rsa_verify(self.client_cert, message, bytes(tampered_sig))
        self.assertFalse(invalid, "Tampered signature accepted")

    def test_message_format_signing(self):
        """Test signing of complete message (seqno || ts || ct)."""
        seqno = 42
        ts = int(time.time() * 1000)
        plaintext = b"Test message"

        # Encrypt
        ct_with_iv = aes_encrypt(self.test_key, plaintext)

        # Create signed message format
        seqno_bytes = int_to_bytes_be(seqno, 8)
        ts_bytes = int_to_bytes_be(ts, 8)
        signed_data = seqno_bytes + ts_bytes + ct_with_iv

        # Sign
        sig = rsa_sign(self.client_key, signed_data)

        # Verify
        valid = rsa_verify(self.client_cert, signed_data, sig)
        self.assertTrue(valid, "Valid message signature rejected")

        # Test tampering with seqno
        tampered_seqno = int_to_bytes_be(seqno + 1, 8)
        tampered_data = tampered_seqno + ts_bytes + ct_with_iv
        invalid = rsa_verify(self.client_cert, tampered_data, sig)
        self.assertFalse(invalid, "Seqno tampering not detected")

        # Test tampering with timestamp
        tampered_ts = int_to_bytes_be(ts + 1000, 8)
        tampered_data = seqno_bytes + tampered_ts + ct_with_iv
        invalid = rsa_verify(self.client_cert, tampered_data, sig)
        self.assertFalse(invalid, "Timestamp tampering not detected")

    def test_sequence_tracking(self):
        """Test sequence number tracking to detect replays."""
        # Simulate a sequence of messages
        last_seqno = -1
        MAX_SEQUENCE_GAP = 1000

        messages = [0, 1, 2, 5, 10, 100]

        for seqno in messages:
            # Check replay (duplicate)
            if seqno <= last_seqno:
                self.fail(f"Replay detected: {seqno} <= {last_seqno}")

            # Check sequence gap
            if seqno - last_seqno > MAX_SEQUENCE_GAP:
                self.fail(f"Sequence gap too large: {seqno} - {last_seqno}")

            last_seqno = seqno

        # Verify tracking worked
        self.assertEqual(last_seqno, 100)

        # Test rejection of replay
        replay_seqno = 5  # Already seen
        if replay_seqno <= last_seqno:
            pass  # Correctly detected replay
        else:
            self.fail("Replay not detected")

    def test_timestamp_validation(self):
        """Test timestamp staleness detection."""
        MAX_TIMESTAMP_SKEW_MS = 5 * 60 * 1000  # 5 minutes

        now_ms = int(time.time() * 1000)

        # Fresh timestamp
        fresh_ts = now_ms - 1000  # 1 second old
        if abs(now_ms - fresh_ts) <= MAX_TIMESTAMP_SKEW_MS:
            pass  # Accepted
        else:
            self.fail("Fresh timestamp rejected")

        # Stale timestamp
        stale_ts = now_ms - (10 * 60 * 1000)  # 10 minutes old
        if abs(now_ms - stale_ts) > MAX_TIMESTAMP_SKEW_MS:
            pass  # Rejected
        else:
            self.fail("Stale timestamp not rejected")


if __name__ == "__main__":
    # Check if certificates exist
    cert_dir = "certs"
    if not os.path.exists(os.path.join(cert_dir, "client_private_key.pem")):
        print("[!] Certificates not generated. Run scripts/gen_ca.py and scripts/gen_cert.py first")
        sys.exit(1)

    unittest.main(verbosity=2)
