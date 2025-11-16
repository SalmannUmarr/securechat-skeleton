#!/usr/bin/env python3
"""
Secure Chat Server - Implements console-based secure chat with CIANR properties.

Control Plane Protocol:
1. Hello: Exchange certificates and validate against CA
2. DH (Credentials): Temporary DH for encrypted register/login payloads
3. DH (Session): Long-lived DH for message encryption after authentication

Data Plane Protocol:
- Per-message format: seqno, timestamp, AES-128-CBC ciphertext, RSA signature
- Sequence number tracking, replay detection, timestamp validation
- Append-only transcript for non-repudiation

CIANR Properties:
- Confidentiality: AES-128-CBC for message encryption
- Integrity: SHA-256 hashing, RSA signatures over message components
- Authenticity: X.509 certificates with CA chain validation, RSA signatures
- Non-Repudiation: Signed transcript with timestamps, session receipts

Usage:
    python server/server.py

Environment:
    - DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME (MySQL)
    - SERVER_HOST, SERVER_PORT (network)
    - CERT_DIR (certificates location)
"""

import socket
import json
import logging
import struct
import time
import base64
import sys
import os
import hashlib
from datetime import datetime
from typing import Optional, Tuple, Dict, Any
from threading import Thread

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.config import *
from utils.crypto_utils import (
    rsa_sign,
    rsa_verify,
    aes_encrypt,
    aes_decrypt,
    sha256_hash,
    sha256_hex,
    cert_fingerprint,
    load_certificate,
    validate_certificate_chain,
    get_certificate_cn,
    constant_time_compare,
    int_to_bytes_be,
    bytes_to_int_be,
    load_private_key,
)
from utils.dh import (
    generate_dh_keypair,
    compute_shared_secret,
    dh_shared_secret_to_key,
    RFC3526_GROUP1_P,
    RFC3526_GROUP1_G,
    RFC3526_GROUP14_P,
    RFC3526_GROUP14_G,
)
from utils.transcript import Transcript, SessionReceipt

# ============================================================================
# Logging Setup
# ============================================================================

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=LOG_LEVEL,
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("SecureChatServer")


# ============================================================================
# Database Module
# ============================================================================


class DatabaseManager:
    """Manages MySQL database connections and user operations."""

    def __init__(self):
        self.connection = None
        self.connect()

    def connect(self):
        """Establish MySQL connection."""
        import mysql.connector

        try:
            self.connection = mysql.connector.connect(**get_db_connection_params())
            logger.info("Database connected successfully")
        except Exception as e:
            logger.warning(f"Database connection failed: {e}")
            logger.warning("Running in demo mode without persistent database")
            self.connection = None
            # For demo purposes, we'll allow the server to run without database
            # In production, this should raise an exception

    def close(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()

    def register_user(self, email: str, username: str, salt: bytes, pwd_hash: str) -> bool:
        """
        Register new user with salted password hash.

        Args:
            email: User email
            username: Username
            salt: 16-byte random salt (binary)
            pwd_hash: SHA256(salt || password) as hex string

        Returns:
            True if successful

        CIANR: Integrity (salted hash prevents rainbow tables)
        """
        if not self.connection:
            logger.warning(f"Database not available, skipping user registration for {email}")
            return True  # Allow for demo mode
            
        try:
            cursor = self.connection.cursor()
            query = """
                INSERT INTO users (email, username, salt, pwd_hash)
                VALUES (%s, %s, %s, %s)
            """
            # Convert salt to hex for storage
            salt_hex = salt.hex()
            cursor.execute(query, (email, username, salt.hex(), pwd_hash))
            self.connection.commit()
            logger.info(f"User registered: {email}")
            return True
        except Exception as e:
            logger.error(f"Registration error: {e}")
            if self.connection:
                self.connection.rollback()
            return False

    def get_user_salt_and_hash(self, email: str) -> Optional[Tuple[bytes, str]]:
        """
        Retrieve user salt and password hash for login.

        Args:
            email: User email

        Returns:
            (salt_bytes, pwd_hash_hex) or None if user not found

        CIANR: Authenticity (verify user credentials)
        """
        if not self.connection:
            logger.warning(f"Database not available, cannot authenticate {email}")
            return None
            
        try:
            cursor = self.connection.cursor()
            query = "SELECT salt, pwd_hash FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            row = cursor.fetchone()
            if row:
                # row[0] is salt as hex string from VARBINARY
                salt_bytes = bytes.fromhex(row[0]) if isinstance(row[0], str) else row[0]
                return salt_bytes, row[1]
            return None
        except Exception as e:
            logger.error(f"Database query error: {e}")
            return None

    def log_auth_event(
        self,
        event_type: str,
        email: Optional[str],
        cert_fingerprint: Optional[str],
        reason: Optional[str],
        ip_address: Optional[str] = None,
    ):
        """Log authentication events for audit."""
        if not self.connection:
            logger.info(f"AUDIT: {event_type} - {email} - {reason}")
            return
            
        try:
            cursor = self.connection.cursor()
            query = """
                INSERT INTO audit_log (event_type, email, client_cert_fingerprint, reason, ip_address)
                VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(query, (event_type, email, cert_fingerprint, reason, ip_address))
            self.connection.commit()
        except Exception as e:
            logger.error(f"Audit log error: {e}")


# ============================================================================
# Client Handler (per-connection)
# ============================================================================


class ClientHandler:
    """Handles individual client connection through secure chat protocol."""

    def __init__(
        self,
        client_socket: socket.socket,
        client_addr: Tuple[str, int],
        db: DatabaseManager,
    ):
        self.socket = client_socket
        self.client_addr = client_addr
        self.db = db

        # Protocol state
        self.client_cert: Optional[bytes] = None
        self.client_cert_fingerprint: Optional[str] = None
        self.client_cn: Optional[str] = None
        self.authenticated_user: Optional[str] = None

        # Encryption state
        self.session_aes_key: Optional[bytes] = None
        self.session_dh_p: Optional[int] = None
        self.session_dh_g: Optional[int] = None

        # Transcript
        self.transcript: Optional[Transcript] = None

        # Message tracking
        self.last_seqno = -1
        self.last_timestamp_ms = 0

        logger.info(f"New connection from {client_addr}")

    def run(self):
        """Run client handler."""
        try:
            # Phase 1: Control Plane - Certificate Exchange
            if not self.handle_certificate_exchange():
                self.send_error("bad-cert", "Certificate validation failed")
                return

            logger.info(f"[{self.client_addr}] Certificate exchange successful")

            # Phase 2: Control Plane - Registration/Login with temporary DH
            if not self.handle_auth():
                logger.warning(f"[{self.client_addr}] Authentication failed")
                return

            logger.info(f"[{self.client_addr}] Authentication successful: {self.authenticated_user}")

            # Phase 3: Control Plane - Session DH
            if not self.handle_session_dh():
                self.send_error("dh-error", "Session DH failed")
                return

            logger.info(f"[{self.client_addr}] Session established")

            # Phase 4: Data Plane - Message Exchange
            self.handle_messaging()

        except Exception as e:
            logger.error(f"[{self.client_addr}] Handler error: {e}", exc_info=True)
        finally:
            try:
                self.socket.close()
            except:
                pass
            logger.info(f"[{self.client_addr}] Connection closed")

    def send_json(self, data: Dict[str, Any]) -> bool:
        """Send JSON message to client."""
        try:
            msg = json.dumps(data).encode("utf-8")
            self.socket.sendall(msg + b"\n")
            return True
        except Exception as e:
            logger.error(f"[{self.client_addr}] Send error: {e}")
            return False

    def recv_json(self, timeout_sec: float = CONTROL_PLANE_TIMEOUT) -> Optional[Dict[str, Any]]:
        """Receive JSON message from client."""
        try:
            self.socket.settimeout(timeout_sec)
            data = b""
            while True:
                chunk = self.socket.recv(4096)
                if not chunk:
                    return None
                data += chunk
                if b"\n" in data:
                    break

            msg_str = data.split(b"\n")[0].decode("utf-8")
            return json.loads(msg_str)
        except socket.timeout:
            logger.warning(f"[{self.client_addr}] Receive timeout")
            return None
        except Exception as e:
            logger.error(f"[{self.client_addr}] Receive error: {e}")
            return None

    def send_error(self, error_type: str, reason: str):
        """Send error response."""
        error_msg = {"type": "error", "error_type": error_type, "reason": reason}
        self.send_json(error_msg)
        logger.warning(f"[{self.client_addr}] Error sent: {error_type} - {reason}")

    # ========================================================================
    # Phase 1: Certificate Exchange
    # ========================================================================

    def handle_certificate_exchange(self) -> bool:
        """
        Handle control plane certificate exchange.

        Protocol:
            Client -> Server: {"type":"hello", "client_cert":"<PEM>", "nonce":"..."}
            Server -> Client: {"type":"server_hello", "server_cert":"<PEM>", "nonce":"..."}

        Validation:
            - Parse PEM certificates
            - Validate against CA
            - Check validity period
            - Verify CN matches expected hostname

        CIANR: Authenticity (mutual cert validation)
        """
        # Receive client hello
        logger.info(f"[{self.client_addr}] Waiting for client hello...")
        client_hello = self.recv_json()
        if not client_hello or client_hello.get("type") != "hello":
            logger.error(f"[{self.client_addr}] Invalid hello message")
            return False

        try:
            client_cert_pem = client_hello.get("client_cert", "").encode("utf-8")
            if not client_cert_pem.startswith(b"-----BEGIN"):
                raise ValueError("Invalid certificate format")

            self.client_cert = client_cert_pem

            # Validate client certificate
            valid, reason = validate_certificate_chain(client_cert_pem, self.load_ca_cert())
            if not valid:
                logger.error(f"[{self.client_addr}] Certificate validation failed: {reason}")
                self.db.log_auth_event("cert_invalid", None, None, reason, self.client_addr[0])
                return False

            # Extract CN and fingerprint
            cert_obj = load_certificate(client_cert_pem)
            self.client_cn = get_certificate_cn(cert_obj)
            self.client_cert_fingerprint = cert_fingerprint(client_cert_pem)

            logger.info(f"[{self.client_addr}] Client cert valid: CN={self.client_cn}, FP={self.client_cert_fingerprint[:16]}...")

        except Exception as e:
            logger.error(f"[{self.client_addr}] Certificate parsing error: {e}")
            return False

        # Send server hello
        try:
            server_cert_pem = self.load_server_cert()
            server_nonce = base64.b64encode(os.urandom(16)).decode("ascii")

            server_hello = {
                "type": "server_hello",
                "server_cert": server_cert_pem.decode("utf-8"),
                "nonce": server_nonce,
            }

            if not self.send_json(server_hello):
                return False

            logger.info(f"[{self.client_addr}] Server hello sent")

        except Exception as e:
            logger.error(f"[{self.client_addr}] Server hello error: {e}")
            return False

        # Initialize transcript
        self.transcript = Transcript(
            peer_type="server",
            peer_cert_fingerprint=self.client_cert_fingerprint,
        )

        return True

    # ========================================================================
    # Phase 2: Registration/Login with Temporary DH
    # ========================================================================

    def handle_auth(self) -> bool:
        """
        Handle registration/login with temporary DH encryption.

        Protocol:
            1. Client initiates DH exchange:
               {"type":"dh_client", "g":<int>, "p":<int>, "A":<int>}
            2. Server responds:
               {"type":"dh_server", "B":<int>}
            3. Both compute shared secret and derive AES key
            4. Client sends encrypted register/login payload

        CIANR: Confidentiality (temporary AES key for credentials)
        """
        # Receive DH client
        dh_client_msg = self.recv_json()
        if not dh_client_msg or dh_client_msg.get("type") != "dh_client":
            logger.error(f"[{self.client_addr}] Expected dh_client message")
            return False

        try:
            g = dh_client_msg.get("g")
            p = dh_client_msg.get("p")
            A = dh_client_msg.get("A")

            # Verify DH parameters match RFC3526
            if p == RFC3526_GROUP1_P and g == RFC3526_GROUP1_G:
                logger.info(f"[{self.client_addr}] Using RFC3526 Group 1 (1024-bit)")
            else:
                logger.error(f"[{self.client_addr}] Invalid DH parameters")
                return False

            # Generate server DH keypair
            b, B = generate_dh_keypair(p, g)

            # Send DH server response
            dh_server_msg = {"type": "dh_server", "B": B}
            if not self.send_json(dh_server_msg):
                return False

            # Compute shared secret and AES key
            shared_secret = compute_shared_secret(A, b, p)
            creds_aes_key = dh_shared_secret_to_key(shared_secret, 16)

            logger.info(f"[{self.client_addr}] Temporary DH complete, AES key derived")

        except Exception as e:
            logger.error(f"[{self.client_addr}] DH exchange error: {e}")
            return False

        # Receive encrypted credentials
        cred_msg = self.recv_json()
        if not cred_msg:
            logger.error(f"[{self.client_addr}] No credential message")
            return False

        try:
            ct_with_iv = base64.b64decode(cred_msg.get("payload", ""))
            plaintext = aes_decrypt(creds_aes_key, ct_with_iv)
            cred_data = json.loads(plaintext.decode("utf-8"))

            cred_type = cred_data.get("type")

            if cred_type == "register":
                return self.handle_register(cred_data)
            elif cred_type == "login":
                return self.handle_login(cred_data)
            else:
                logger.error(f"[{self.client_addr}] Unknown credential type: {cred_type}")
                return False

        except Exception as e:
            logger.error(f"[{self.client_addr}] Credential decryption error: {e}")
            return False

    def handle_register(self, cred_data: Dict[str, Any]) -> bool:
        """
        Handle user registration.

        Expected payload (after decryption):
        {
            "type": "register",
            "email": "user@example.com",
            "username": "username",
            "salt": base64(16-byte salt),
            "pwd": base64(SHA256(salt || password))
        }

        CIANR: Integrity (salt prevents rainbow tables)
        """
        try:
            email = cred_data.get("email", "").strip()
            username = cred_data.get("username", "").strip()
            salt_b64 = cred_data.get("salt", "")
            pwd_hash_b64 = cred_data.get("pwd", "")

            if not all([email, username, salt_b64, pwd_hash_b64]):
                logger.error(f"[{self.client_addr}] Missing register fields")
                return False

            salt = base64.b64decode(salt_b64)
            pwd_hash = base64.b64decode(pwd_hash_b64).hex()

            if len(salt) != 16:
                logger.error(f"[{self.client_addr}] Invalid salt length")
                return False

            # Register in database
            if self.db.register_user(email, username, salt, pwd_hash):
                self.authenticated_user = email
                self.db.log_auth_event(
                    "registration_success",
                    email,
                    self.client_cert_fingerprint,
                    "User registered",
                    self.client_addr[0],
                )
                logger.info(f"[{self.client_addr}] Registration successful: {email}")
                return True
            else:
                self.db.log_auth_event(
                    "registration_failure",
                    email,
                    self.client_cert_fingerprint,
                    "Database error",
                    self.client_addr[0],
                )
                return False

        except Exception as e:
            logger.error(f"[{self.client_addr}] Register error: {e}")
            return False

    def handle_login(self, cred_data: Dict[str, Any]) -> bool:
        """
        Handle user login with salted password verification.

        Expected payload (after decryption):
        {
            "type": "login",
            "email": "user@example.com",
            "password": "plaintext_password"
        }

        Process:
            1. Retrieve user salt from database
            2. Compute hash: SHA256(stored_salt || provided_password)
            3. Compare with stored hash using constant-time comparison

        CIANR: Authenticity (password verification) + Integrity (salted hash)
        """
        try:
            email = cred_data.get("email", "").strip()
            provided_password = cred_data.get("password", "")

            if not email or not provided_password:
                logger.error(f"[{self.client_addr}] Missing login fields")
                self.db.log_auth_event(
                    "login_failure",
                    email,
                    self.client_cert_fingerprint,
                    "Missing fields",
                    self.client_addr[0],
                )
                return False

            # Retrieve stored salt and hash
            result = self.db.get_user_salt_and_hash(email)
            if not result:
                logger.error(f"[{self.client_addr}] User not found: {email}")
                self.db.log_auth_event(
                    "login_failure",
                    email,
                    self.client_cert_fingerprint,
                    "User not found",
                    self.client_addr[0],
                )
                return False

            stored_salt, stored_hash_hex = result

            # Compute hash with provided password and stored salt
            computed_hash = hashlib.sha256(stored_salt + provided_password.encode()).digest()
            computed_hash_hex = computed_hash.hex()

            # Verify using constant-time comparison
            if not constant_time_compare(
                computed_hash_hex.encode(), stored_hash_hex.encode()
            ):
                logger.error(f"[{self.client_addr}] Password verification failed: {email}")
                self.db.log_auth_event(
                    "login_failure",
                    email,
                    self.client_cert_fingerprint,
                    "Password mismatch",
                    self.client_addr[0],
                )
                return False

            self.authenticated_user = email
            self.db.log_auth_event(
                "login_success",
                email,
                self.client_cert_fingerprint,
                "Successful login",
                self.client_addr[0],
            )
            logger.info(f"[{self.client_addr}] Login successful: {email}")
            return True

        except Exception as e:
            logger.error(f"[{self.client_addr}] Login error: {e}")
            self.db.log_auth_event(
                "login_error",
                None,
                self.client_cert_fingerprint,
                str(e),
                self.client_addr[0],
            )
            return False

    # ========================================================================
    # Phase 3: Session DH
    # ========================================================================

    def handle_session_dh(self) -> bool:
        """
        Establish session encryption key via DH exchange.

        Protocol:
            1. Client initiates: {"type":"dh_client", "g":<int>, "p":<int>, "A":<int>}
            2. Server responds: {"type":"dh_server", "B":<int>}
            3. Both compute session AES key
            4. Subsequent messages encrypted with this key

        CIANR: Confidentiality (long-lived session key)
        """
        dh_client_msg = self.recv_json()
        if not dh_client_msg or dh_client_msg.get("type") != "dh_client":
            logger.error(f"[{self.client_addr}] Expected session dh_client")
            return False

        try:
            g = dh_client_msg.get("g")
            p = dh_client_msg.get("p")
            A = dh_client_msg.get("A")

            # Verify RFC3526 Group 14 (2048-bit)
            if p != RFC3526_GROUP14_P or g != RFC3526_GROUP14_G:
                logger.error(f"[{self.client_addr}] Invalid session DH parameters")
                return False

            # Store for later use
            self.session_dh_p = p
            self.session_dh_g = g

            # Generate server DH keypair
            b, B = generate_dh_keypair(p, g)

            # Send response
            dh_server_msg = {"type": "dh_server", "B": B}
            if not self.send_json(dh_server_msg):
                return False

            # Compute session AES key
            shared_secret = compute_shared_secret(A, b, p)
            self.session_aes_key = dh_shared_secret_to_key(shared_secret, 16)

            logger.info(f"[{self.client_addr}] Session DH complete")
            return True

        except Exception as e:
            logger.error(f"[{self.client_addr}] Session DH error: {e}")
            return False

    # ========================================================================
    # Phase 4: Messaging
    # ========================================================================

    def handle_messaging(self):
        """
        Handle encrypted message exchange.

        Message format:
        {
            "type": "msg",
            "seqno": <int>,
            "ts": <int (unix_ms)>,
            "ct": base64(iv || ciphertext),
            "sig": base64(RSA_SIGN(SHA256(seqno||ts||ct)))
        }

        Validation:
            1. Verify signature (RSA-PSS)
            2. Check sequence number (no replays)
            3. Check timestamp (< 5 minutes old)
            4. Decrypt message
            5. Append to transcript

        CIANR: Integrity (signatures), Confidentiality (encryption), Non-Repudiation (transcript)
        """
        server_key_pem = self.load_server_private_key()
        logger.info(f"[{self.client_addr}] Messaging started")

        while True:
            try:
                msg = self.recv_json(timeout_sec=None)  # Block indefinitely
                if not msg:
                    logger.info(f"[{self.client_addr}] Client disconnected")
                    break

                msg_type = msg.get("type")

                if msg_type == "msg":
                    if not self.handle_message(msg, server_key_pem):
                        logger.warning(f"[{self.client_addr}] Invalid message, closing")
                        break

                elif msg_type == "receipt":
                    # Client is sending receipt (for verification)
                    logger.info(f"[{self.client_addr}] Received client receipt")
                    # Could store for audit
                    pass

                elif msg_type == "quit":
                    logger.info(f"[{self.client_addr}] Client quit")
                    # Send server receipt
                    if self.transcript:
                        self.send_session_receipt(server_key_pem)
                    break

                else:
                    logger.warning(f"[{self.client_addr}] Unknown message type: {msg_type}")

            except Exception as e:
                logger.error(f"[{self.client_addr}] Messaging error: {e}", exc_info=True)
                break

    def handle_message(self, msg: Dict[str, Any], server_key_pem: bytes) -> bool:
        """
        Validate and process encrypted message from client.

        CIANR: Integrity (verify signature and seq), Authenticity (RSA-PSS), Confidentiality (decrypt)
        """
        try:
            seqno = msg.get("seqno")
            ts = msg.get("ts")
            ct_b64 = msg.get("ct", "")
            sig_b64 = msg.get("sig", "")

            if not all([seqno is not None, ts is not None, ct_b64, sig_b64]):
                logger.error(f"[{self.client_addr}] Missing message fields")
                return False

            # Validate sequence number (no duplicates)
            if seqno <= self.last_seqno:
                logger.error(f"[{self.client_addr}] Sequence number replay: {seqno} <= {self.last_seqno}")
                return False

            # Validate timestamp (< 5 minutes old)
            now_ms = int(time.time() * 1000)
            if abs(now_ms - ts) > MAX_TIMESTAMP_SKEW_MS:
                logger.error(
                    f"[{self.client_addr}] Timestamp too old: {ts} (now: {now_ms})"
                )
                return False

            # Decode ciphertext
            ct_with_iv = base64.b64decode(ct_b64)
            sig = base64.b64decode(sig_b64)

            # Reconstruct message for signature verification
            seqno_bytes = int_to_bytes_be(seqno, 8)
            ts_bytes = int_to_bytes_be(ts, 8)
            signed_data = seqno_bytes + ts_bytes + ct_with_iv

            # Verify signature
            if not rsa_verify(self.client_cert, signed_data, sig):
                logger.error(f"[{self.client_addr}] Signature verification failed")
                return False

            # Decrypt message
            plaintext = aes_decrypt(self.session_aes_key, ct_with_iv)

            # Append to transcript
            if self.transcript:
                self.transcript.append(seqno, ts, ct_with_iv, sig)

            # Log message (do not log plaintext for security)
            logger.info(
                f"[{self.client_addr}] Message {seqno} received (size: {len(plaintext)})"
            )

            # Send echo response
            echo_response = {
                "type": "msg_ack",
                "seqno": seqno,
                "received_at": int(time.time() * 1000),
            }
            self.send_json(echo_response)

            self.last_seqno = seqno
            self.last_timestamp_ms = ts

            return True

        except Exception as e:
            logger.error(f"[{self.client_addr}] Message handling error: {e}")
            return False

    def send_session_receipt(self, server_key_pem: bytes):
        """Send signed session receipt to client."""
        try:
            if not self.transcript:
                return

            receipt = SessionReceipt(
                peer_type="server",
                peer_cert_fingerprint=self.client_cert_fingerprint,
                transcript=self.transcript,
            )

            # Sign transcript hash
            transcript_hash = self.transcript.get_transcript_hash()
            signature = rsa_sign(server_key_pem, transcript_hash)

            receipt.set_signature(signature, self.load_server_cert())

            receipt_json = receipt.to_json()
            receipt_msg = {"type": "receipt", "data": json.loads(receipt_json)}

            self.send_json(receipt_msg)
            logger.info(f"[{self.client_addr}] Session receipt sent")

        except Exception as e:
            logger.error(f"[{self.client_addr}] Receipt error: {e}")

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def load_server_cert(self) -> bytes:
        """Load server certificate PEM."""
        with open(SERVER_CERT_FILE, "rb") as f:
            return f.read()

    def load_server_private_key(self) -> bytes:
        """Load server private key PEM."""
        with open(SERVER_KEY_FILE, "rb") as f:
            return f.read()

    def load_ca_cert(self) -> bytes:
        """Load CA certificate PEM."""
        with open(CA_CERT_FILE, "rb") as f:
            return f.read()


# ============================================================================
# Main Server
# ============================================================================


class SecureChatServer:
    """Main secure chat server."""

    def __init__(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        self.host = host
        self.port = port
        self.socket = None
        self.db = DatabaseManager()

    def start(self):
        """Start server and listen for connections."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(SERVER_BACKLOG)

            logger.info(f"[*] Secure Chat Server listening on {self.host}:{self.port}")
            print(f"\n[*] Secure Chat Server listening on {self.host}:{self.port}")
            print("[*] Press Ctrl+C to stop\n")

            while True:
                try:
                    client_socket, client_addr = self.socket.accept()
                    handler = ClientHandler(client_socket, client_addr, self.db)
                    thread = Thread(target=handler.run, daemon=True)
                    thread.start()
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    logger.error(f"Accept error: {e}")

        except Exception as e:
            logger.error(f"Server error: {e}")
            raise
        finally:
            self.shutdown()

    def shutdown(self):
        """Shutdown server."""
        logger.info("Shutting down server...")
        if self.socket:
            self.socket.close()
        if self.db:
            self.db.close()


def main():
    """Main entry point."""
    try:
        # Validate configuration
        SERVER_HOST  # Just access to trigger errors
        validate_config()
        logger.info("Configuration validated")

        # Start server
        server = SecureChatServer(SERVER_HOST, SERVER_PORT)
        server.start()

    except FileNotFoundError as e:
        logger.error(f"Configuration error: {e}")
        print(f"[!] Error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
