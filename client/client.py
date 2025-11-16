#!/usr/bin/env python3
"""
Secure Chat Client - Implements client-side protocol for secure communication.

Control Plane Protocol:
1. Hello: Exchange certificates with server
2. DH (Credentials): Temporary DH for encrypted register/login
3. DH (Session): Long-lived DH for message encryption

Data Plane Protocol:
- Per-message: seqno, timestamp, AES-128-CBC ciphertext, RSA signature
- Interactive console: send messages, view transcript, export receipt

CIANR Properties:
- Confidentiality: AES-128-CBC encryption
- Integrity: SHA-256 + RSA signatures
- Authenticity: X.509 certificates with CA validation
- Non-Repudiation: Signed transcript with timestamps

Usage:
    python client/client.py [--server host] [--port port]
"""

import socket
import json
import logging
import time
import base64
import sys
import os
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.config import *
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
    int_to_bytes_be,
    bytes_to_int_be,
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
# Logging
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
logger = logging.getLogger("SecureChatClient")


# ============================================================================
# Secure Chat Client
# ============================================================================


class SecureChatClient:
    """Secure chat client with certificate exchange and encrypted messaging."""

    def __init__(self, server_host: str = SERVER_HOST, server_port: int = SERVER_PORT):
        self.server_host = server_host
        self.server_port = server_port
        self.socket: Optional[socket.socket] = None

        # Protocol state
        self.server_cert: Optional[bytes] = None
        self.server_cert_fingerprint: Optional[str] = None

        # Encryption state
        self.session_aes_key: Optional[bytes] = None

        # Transcript
        self.transcript: Optional[Transcript] = None
        self.last_seqno = -1

        logger.info(f"Client initialized: {server_host}:{server_port}")

    def connect(self) -> bool:
        """Establish TCP connection to server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            logger.info(f"Connected to {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def disconnect(self):
        """Close connection to server."""
        if self.socket:
            try:
                self.socket.close()
                logger.info("Disconnected from server")
            except:
                pass

    def send_json(self, data: Dict[str, Any]) -> bool:
        """Send JSON message to server."""
        try:
            msg = json.dumps(data).encode("utf-8")
            self.socket.sendall(msg + b"\n")
            return True
        except Exception as e:
            logger.error(f"Send error: {e}")
            return False

    def recv_json(self, timeout_sec: float = CONTROL_PLANE_TIMEOUT) -> Optional[Dict[str, Any]]:
        """Receive JSON message from server."""
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
            logger.warning("Receive timeout")
            return None
        except Exception as e:
            logger.error(f"Receive error: {e}")
            return None

    # ========================================================================
    # Phase 1: Certificate Exchange
    # ========================================================================

    def exchange_certificates(self) -> bool:
        """
        Exchange certificates with server.

        CIANR: Authenticity (mutual cert validation)
        """
        try:
            logger.info("Starting certificate exchange...")
            client_cert_pem = self.load_client_cert()
            client_nonce = base64.b64encode(os.urandom(16)).decode("ascii")

            # Send hello
            hello_msg = {
                "type": "hello",
                "client_cert": client_cert_pem.decode("utf-8"),
                "nonce": client_nonce,
            }
            if not self.send_json(hello_msg):
                return False

            # Receive server hello
            server_hello = self.recv_json()
            if not server_hello or server_hello.get("type") != "server_hello":
                logger.error("Invalid server hello")
                return False

            server_cert_pem = server_hello.get("server_cert", "").encode("utf-8")

            # Validate server certificate
            valid, reason = validate_certificate_chain(server_cert_pem, self.load_ca_cert())
            if not valid:
                logger.error(f"Server certificate validation failed: {reason}")
                return False

            self.server_cert = server_cert_pem
            self.server_cert_fingerprint = cert_fingerprint(server_cert_pem)

            logger.info(f"Server certificate valid: FP={self.server_cert_fingerprint[:16]}...")

            # Initialize transcript
            self.transcript = Transcript(
                peer_type="client",
                peer_cert_fingerprint=self.server_cert_fingerprint,
            )

            return True

        except Exception as e:
            logger.error(f"Certificate exchange error: {e}")
            return False

    # ========================================================================
    # Phase 2: Registration or Login
    # ========================================================================

    def register_or_login(self) -> bool:
        """
        Interactive registration or login with temporary DH.

        CIANR: Confidentiality (temporary AES key)
        """
        print("\n[*] Register or Login?")
        choice = input("  (r)egister or (l)ogin: ").strip().lower()

        # Perform temporary DH first
        creds_aes_key = self.temp_dh()
        if not creds_aes_key:
            logger.error("Temporary DH failed")
            return False

        if choice == "r":
            return self.register(creds_aes_key)
        elif choice == "l":
            return self.login(creds_aes_key)
        else:
            print("[!] Invalid choice")
            return False

    def register(self, creds_aes_key: bytes) -> bool:
        """Register new user with encrypted credentials."""
        try:
            logger.info("Starting registration...")
            email = input("  Email: ").strip()
            username = input("  Username: ").strip()
            password = input("  Password: ").strip()

            if not all([email, username, password]):
                print("[!] Missing fields")
                return False

            # Generate salt and hash
            salt = os.urandom(16)
            pwd_hash = hashlib.sha256(salt + password.encode()).digest()

            # Prepare registration payload
            reg_payload = {
                "type": "register",
                "email": email,
                "username": username,
                "salt": base64.b64encode(salt).decode("ascii"),
                "pwd": base64.b64encode(pwd_hash).decode("ascii"),
            }

            # Encrypt payload
            plaintext = json.dumps(reg_payload).encode("utf-8")
            ct_with_iv = aes_encrypt(creds_aes_key, plaintext)

            # Send encrypted credentials
            cred_msg = {
                "type": "register",
                "payload": base64.b64encode(ct_with_iv).decode("ascii"),
            }

            if not self.send_json(cred_msg):
                logger.error("Failed to send registration payload")
                return False

            print("[+] Registration successful")
            logger.info(f"Registered: {email}")
            return True

        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False

    def login(self, creds_aes_key: bytes) -> bool:
        """Login existing user with encrypted credentials."""
        try:
            logger.info("Starting login...")
            email = input("  Email: ").strip()
            password = input("  Password: ").strip()

            if not email or not password:
                print("[!] Missing fields")
                return False

            # For login, we send email+password to server
            # Server looks up user, retrieves stored salt, recomputes hash, and compares
            # Client sends: email and plaintext password (over encrypted channel)
            # Server does the hashing with stored salt

            nonce = base64.b64encode(os.urandom(16)).decode("ascii")

            login_payload = {
                "type": "login",
                "email": email,
                "password": password,  # Plaintext password (encrypted in transit)
                "nonce": nonce,
            }

            # Encrypt payload
            plaintext = json.dumps(login_payload).encode("utf-8")
            ct_with_iv = aes_encrypt(creds_aes_key, plaintext)

            # Send encrypted credentials
            cred_msg = {
                "type": "login",
                "payload": base64.b64encode(ct_with_iv).decode("ascii"),
            }

            if not self.send_json(cred_msg):
                logger.error("Failed to send login payload")
                return False

            print("[+] Login successful")
            logger.info(f"Logged in: {email}")
            return True

        except Exception as e:
            logger.error(f"Login error: {e}")
            return False

    def temp_dh(self) -> Optional[bytes]:
        """
        Perform temporary DH exchange for credential encryption.

        Returns:
            AES-128 key for encrypting credentials, or None on failure

        CIANR: Confidentiality (derives temporary AES key)
        """
        try:
            logger.info("Performing temporary DH...")
            g = RFC3526_GROUP1_G
            p = RFC3526_GROUP1_P

            # Generate client keypair
            a, A = generate_dh_keypair(p, g)

            # Send DH client
            dh_client_msg = {"type": "dh_client", "g": g, "p": p, "A": A}
            if not self.send_json(dh_client_msg):
                return None

            # Receive DH server response
            dh_server_msg = self.recv_json()
            if not dh_server_msg or dh_server_msg.get("type") != "dh_server":
                logger.error("Invalid DH server response")
                return None

            B = dh_server_msg.get("B")
            shared_secret = compute_shared_secret(B, a, p)
            creds_aes_key = dh_shared_secret_to_key(shared_secret, 16)

            logger.info("Temporary DH complete")
            return creds_aes_key

        except Exception as e:
            logger.error(f"Temp DH error: {e}")
            return None

    # ========================================================================
    # Phase 3: Session DH
    # ========================================================================

    def session_dh(self) -> bool:
        """
        Establish session encryption key.

        CIANR: Confidentiality (long-lived session key)
        """
        try:
            logger.info("Performing session DH...")
            g = RFC3526_GROUP14_G
            p = RFC3526_GROUP14_P

            # Generate client keypair
            a, A = generate_dh_keypair(p, g)

            # Send DH client
            dh_client_msg = {"type": "dh_client", "g": g, "p": p, "A": A}
            if not self.send_json(dh_client_msg):
                return False

            # Receive DH server response
            dh_server_msg = self.recv_json()
            if not dh_server_msg or dh_server_msg.get("type") != "dh_server":
                logger.error("Invalid DH server response")
                return False

            B = dh_server_msg.get("B")
            shared_secret = compute_shared_secret(B, a, p)
            self.session_aes_key = dh_shared_secret_to_key(shared_secret, 16)

            logger.info("Session DH complete")
            return True

        except Exception as e:
            logger.error(f"Session DH error: {e}")
            return False

    # ========================================================================
    # Messaging
    # ========================================================================

    def send_message(self, text: str) -> bool:
        """Send encrypted message to server."""
        try:
            # Prepare message
            seqno = self.last_seqno + 1
            ts = int(time.time() * 1000)
            plaintext = text.encode("utf-8")

            # Encrypt
            ct_with_iv = aes_encrypt(self.session_aes_key, plaintext)

            # Prepare data for signature
            seqno_bytes = int_to_bytes_be(seqno, 8)
            ts_bytes = int_to_bytes_be(ts, 8)
            signed_data = seqno_bytes + ts_bytes + ct_with_iv

            # Sign
            client_key_pem = self.load_client_private_key()
            sig = rsa_sign(client_key_pem, signed_data)

            # Send message
            msg = {
                "type": "msg",
                "seqno": seqno,
                "ts": ts,
                "ct": base64.b64encode(ct_with_iv).decode("ascii"),
                "sig": base64.b64encode(sig).decode("ascii"),
            }

            if not self.send_json(msg):
                return False

            # Append to transcript
            if self.transcript:
                self.transcript.append(seqno, ts, ct_with_iv, sig)

            self.last_seqno = seqno
            logger.info(f"Message {seqno} sent")
            return True

        except Exception as e:
            logger.error(f"Send message error: {e}")
            return False

    def interactive_messaging(self):
        """Interactive messaging loop."""
        print("\n[*] Connected to secure chat server")
        print("[*] Type messages to send, 'quit' to exit, 'receipt' to get receipt\n")

        while True:
            try:
                msg_text = input("> ")

                if msg_text.lower() == "quit":
                    print("[*] Exiting...")
                    quit_msg = {"type": "quit"}
                    self.send_json(quit_msg)
                    break

                elif msg_text.lower() == "receipt":
                    print("[*] Requesting session receipt...")
                    receipt_msg = self.recv_json(timeout_sec=10)
                    if receipt_msg and receipt_msg.get("type") == "receipt":
                        print("\n[+] Session Receipt:")
                        print(json.dumps(receipt_msg.get("data"), indent=2))
                    continue

                elif msg_text.strip():
                    if self.send_message(msg_text):
                        print("    [sent]")
                        # Wait for ACK
                        ack = self.recv_json(timeout_sec=5)
                        if ack and ack.get("type") == "msg_ack":
                            logger.info(f"Received ACK for seq {ack.get('seqno')}")

            except KeyboardInterrupt:
                print("\n[*] Interrupted")
                break
            except Exception as e:
                logger.error(f"Messaging error: {e}")
                break

    # ========================================================================
    # Export Transcript
    # ========================================================================

    def export_transcript(self, filename: str = "transcript.txt"):
        """Export transcript to file."""
        try:
            os.makedirs(TRANSCRIPT_DIR, exist_ok=True)
            filepath = os.path.join(TRANSCRIPT_DIR, filename)

            if self.transcript:
                self.transcript.export_lines(filepath)
                print(f"[+] Transcript exported to {filepath}")
                logger.info(f"Transcript exported: {filepath}")
        except Exception as e:
            logger.error(f"Export error: {e}")

    # ========================================================================
    # Utilities
    # ========================================================================

    def load_client_cert(self) -> bytes:
        """Load client certificate."""
        with open(CLIENT_CERT_FILE, "rb") as f:
            return f.read()

    def load_client_private_key(self) -> bytes:
        """Load client private key."""
        with open(CLIENT_KEY_FILE, "rb") as f:
            return f.read()

    def load_ca_cert(self) -> bytes:
        """Load CA certificate."""
        with open(CA_CERT_FILE, "rb") as f:
            return f.read()

    def run(self):
        """Run interactive client session."""
        try:
            if not self.connect():
                print("[!] Connection failed")
                return

            if not self.exchange_certificates():
                print("[!] Certificate exchange failed")
                return

            if not self.register_or_login():
                print("[!] Authentication failed")
                return

            if not self.session_dh():
                print("[!] Session DH failed")
                return

            self.interactive_messaging()

            # Export transcript
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.export_transcript(f"transcript_{timestamp}.txt")

        except Exception as e:
            logger.error(f"Client error: {e}", exc_info=True)
        finally:
            self.disconnect()


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Secure Chat Client")
    parser.add_argument("--server", default=SERVER_HOST, help="Server host")
    parser.add_argument("--port", type=int, default=SERVER_PORT, help="Server port")

    args = parser.parse_args()

    try:
        validate_config()
        client = SecureChatClient(args.server, args.port)
        client.run()
    except FileNotFoundError as e:
        logger.error(f"Configuration error: {e}")
        print(f"[!] Error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
