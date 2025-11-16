"""
Transcript Module - Provides append-only transcript and receipt generation for non-repudiation.

Features:
- Append-only transcript: seqno|ts|base64(ct)|base64(sig)|peer-cert-fingerprint
- Transcript hashing: SHA256(concat(lines with '\n'))
- Receipt generation: Signed summary of session with transcript hash
- Offline verification: Verify transcript correctness and receipt validity

CIANR Mapping:
- Integrity: Append-only log with cryptographic hashing
- Non-Repudiation: Signed receipts with timestamps and peer identities
- Authenticity: Certificates embedded in transcript fingerprints

Protocol:
At end of session, both parties:
1. Compute TranscriptHash = SHA256(concat(lines with '\n'))
2. Sign TranscriptHash with own private key
3. Exchange SessionReceipt JSON with signature
4. Archive transcript and receipt for offline verification
"""

import hashlib
import base64
import json
from typing import List, Dict, Any, Optional
from datetime import datetime


class Transcript:
    """
    Append-only session transcript for non-repudiation.

    Each line format:
        seqno|ts|base64(ct)|base64(sig)|peer-cert-fingerprint

    Examples:
        0|1700000000123|AeF1d2k/JJ8=...|sig_base64...|sha256_fingerprint...
        1|1700000000456|BfG2e3l/KK9=...|sig_base64...|sha256_fingerprint...
    """

    def __init__(self, peer_type: str, peer_cert_fingerprint: str):
        """
        Initialize transcript.

        Args:
            peer_type: "client" or "server" (perspective of transcript owner)
            peer_cert_fingerprint: SHA256 fingerprint of peer's certificate
        """
        self.peer_type = peer_type
        self.peer_cert_fingerprint = peer_cert_fingerprint
        self.lines: List[str] = []
        self.message_count = 0

    def append(
        self,
        seqno: int,
        ts: int,
        ciphertext_with_iv: bytes,
        signature: bytes,
    ) -> None:
        """
        Append message record to transcript.

        Args:
            seqno: Message sequence number (8-byte big-endian integer)
            ts: Unix millisecond timestamp (8-byte big-endian integer)
            ciphertext_with_iv: Encrypted message (iv || ct)
            signature: RSA signature over seqno||ts||ct

        CIANR: Integrity (append-only), Non-Repudiation (signatures)
        """
        ct_b64 = base64.b64encode(ciphertext_with_iv).decode("ascii")
        sig_b64 = base64.b64encode(signature).decode("ascii")

        line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{self.peer_cert_fingerprint}"
        self.lines.append(line)
        self.message_count += 1

    def get_lines(self) -> List[str]:
        """Get all transcript lines."""
        return self.lines.copy()

    def get_transcript_hash(self) -> bytes:
        """
        Compute transcript hash: SHA256(concat(lines with '\n')).

        Returns:
            32-byte SHA-256 digest

        CIANR: Integrity
        """
        if not self.lines:
            transcript_data = b""
        else:
            transcript_data = "\n".join(self.lines).encode("utf-8")

        return hashlib.sha256(transcript_data).digest()

    def get_transcript_hash_hex(self) -> str:
        """Get transcript hash as hex string."""
        return self.get_transcript_hash().hex()

    def export_lines(self, filepath: str) -> None:
        """
        Export transcript lines to file (one per line).

        Args:
            filepath: Path to save transcript
        """
        with open(filepath, "w") as f:
            for line in self.lines:
                f.write(line + "\n")

    def export_json(self, filepath: str) -> None:
        """
        Export transcript as JSON (for documentation).

        Args:
            filepath: Path to save JSON
        """
        data = {
            "peer_type": self.peer_type,
            "peer_cert_fingerprint": self.peer_cert_fingerprint,
            "message_count": self.message_count,
            "transcript_hash": self.get_transcript_hash_hex(),
            "lines": self.lines,
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def import_lines(filepath: str) -> "Transcript":
        """
        Import transcript from file.

        Args:
            filepath: Path to transcript file

        Returns:
            Transcript object with lines loaded
        """
        with open(filepath, "r") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]

        if not lines:
            raise ValueError("Empty transcript file")

        # Parse first line to get peer info
        first_parts = lines[0].split("|")
        peer_cert_fingerprint = first_parts[-1]

        # Create transcript with dummy peer_type (will be in receipt)
        transcript = Transcript("unknown", peer_cert_fingerprint)
        transcript.lines = lines
        transcript.message_count = len(lines)

        return transcript


class SessionReceipt:
    """
    Cryptographic receipt for session authentication and non-repudiation.

    Format:
    {
        "type": "receipt",
        "peer": "client" or "server",
        "created_at": ISO timestamp,
        "first_seqno": int,
        "last_seqno": int,
        "message_count": int,
        "transcript_hash": hex string,
        "peer_cert_fingerprint": sha256 fingerprint,
        "signature": base64(RSA_SIGN(transcript_hash)),
        "signer_cert": base64(certificate PEM) [optional, for verification]
    }

    CIANR Mapping:
    - Non-Repudiation: Signed by peer's private key
    - Integrity: Covers transcript hash
    - Authenticity: Certificate identifies peer
    """

    def __init__(
        self,
        peer_type: str,
        peer_cert_fingerprint: str,
        transcript: Optional[Transcript] = None,
    ):
        """
        Initialize receipt.

        Args:
            peer_type: "client" or "server"
            peer_cert_fingerprint: Peer's certificate fingerprint
            transcript: Optional transcript to link to receipt
        """
        self.peer_type = peer_type
        self.peer_cert_fingerprint = peer_cert_fingerprint
        self.transcript = transcript
        self.created_at = datetime.utcnow().isoformat() + "Z"
        self.signature: Optional[bytes] = None
        self.signer_cert: Optional[bytes] = None

    def set_signature(self, signature: bytes, signer_cert: Optional[bytes] = None):
        """
        Set receipt signature and optional certificate.

        Args:
            signature: Binary RSA signature over transcript hash
            signer_cert: PEM certificate of signer (for offline verification)

        CIANR: Non-Repudiation
        """
        self.signature = signature
        self.signer_cert = signer_cert

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert receipt to dictionary (for JSON serialization).

        Returns:
            Dictionary representation

        CIANR: Non-Repudiation (includes all necessary verification data)
        """
        if not self.transcript:
            raise ValueError("Transcript not set on receipt")

        if not self.signature:
            raise ValueError("Signature not set on receipt")

        first_seqno, last_seqno = None, None
        if self.transcript.lines:
            first_parts = self.transcript.lines[0].split("|")
            last_parts = self.transcript.lines[-1].split("|")
            first_seqno = int(first_parts[0])
            last_seqno = int(last_parts[0])

        receipt_dict = {
            "type": "receipt",
            "peer": self.peer_type,
            "created_at": self.created_at,
            "first_seqno": first_seqno,
            "last_seqno": last_seqno,
            "message_count": self.transcript.message_count,
            "transcript_hash": self.transcript.get_transcript_hash_hex(),
            "peer_cert_fingerprint": self.peer_cert_fingerprint,
            "signature": base64.b64encode(self.signature).decode("ascii"),
        }

        if self.signer_cert:
            receipt_dict["signer_cert"] = base64.b64encode(self.signer_cert).decode(
                "ascii"
            )

        return receipt_dict

    def to_json(self) -> str:
        """Convert receipt to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def to_json_file(self, filepath: str) -> None:
        """Export receipt to JSON file."""
        with open(filepath, "w") as f:
            f.write(self.to_json())

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "SessionReceipt":
        """Load receipt from dictionary (from JSON)."""
        receipt = SessionReceipt(
            peer_type=data["peer"],
            peer_cert_fingerprint=data["peer_cert_fingerprint"],
        )
        receipt.created_at = data["created_at"]
        receipt.signature = base64.b64decode(data["signature"])

        if "signer_cert" in data:
            receipt.signer_cert = base64.b64decode(data["signer_cert"])

        return receipt

    @staticmethod
    def from_json_file(filepath: str) -> "SessionReceipt":
        """Load receipt from JSON file."""
        with open(filepath, "r") as f:
            data = json.load(f)
        return SessionReceipt.from_dict(data)


# Verification utilities
def verify_transcript_receipt(
    receipt: SessionReceipt,
    transcript: Transcript,
    peer_cert_pem: bytes,
) -> tuple[bool, str]:
    """
    Verify session receipt and transcript integrity.

    Args:
        receipt: Session receipt
        transcript: Session transcript
        peer_cert_pem: PEM certificate of receipt signer

    Returns:
        (is_valid, reason_if_invalid)

    Checks:
        1. Transcript hash matches receipt
        2. Signature is valid over transcript hash
        3. Certificate matches fingerprint
        4. Message counts match

    CIANR: Non-Repudiation (verify signatures)
    """
    from utils.crypto_utils import (
        cert_fingerprint,
        sha256_hex,
        rsa_verify,
    )

    # Verify peer certificate
    cert_fp = cert_fingerprint(peer_cert_pem)
    if cert_fp != receipt.peer_cert_fingerprint:
        return False, f"Certificate fingerprint mismatch: {cert_fp} != {receipt.peer_cert_fingerprint}"

    # Verify transcript hash
    transcript_hash = transcript.get_transcript_hash()
    receipt_hash = bytes.fromhex(receipt.to_dict()["transcript_hash"])

    if transcript_hash != receipt_hash:
        return False, "Transcript hash mismatch"

    # Verify signature
    if not receipt.signature:
        return False, "Receipt missing signature"

    sig_valid = rsa_verify(peer_cert_pem, transcript_hash, receipt.signature)
    if not sig_valid:
        return False, "Receipt signature verification failed"

    # Verify message count
    if receipt.to_dict()["message_count"] != transcript.message_count:
        return False, "Message count mismatch"

    return True, "Receipt verified"
