"""
Client Configuration Module

Manages configuration for the secure chat client.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# ============================================================================
# Server Connection Configuration
# ============================================================================

SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = int(os.getenv("SERVER_PORT", 5000))
CONNECTION_TIMEOUT = int(os.getenv("CONNECTION_TIMEOUT", 30))

# ============================================================================
# Certificate Configuration
# ============================================================================

CERT_DIR = os.getenv("CERT_DIR", "certs")
CLIENT_CERT_FILE = os.path.join(CERT_DIR, "client_cert.pem")
CLIENT_KEY_FILE = os.path.join(CERT_DIR, "client_private_key.pem")
CA_CERT_FILE = os.path.join(CERT_DIR, "ca_cert.pem")
SERVER_CERT_FILE = os.path.join(CERT_DIR, "server_cert.pem")

# ============================================================================
# Protocol Configuration
# ============================================================================

# Control plane handshake timeout (seconds)
CONTROL_PLANE_TIMEOUT = 30

# Message sequence number validation
MAX_SEQUENCE_GAP = 1000
MAX_TIMESTAMP_SKEW_MS = 5 * 60 * 1000  # 5 minutes

# DH exchange parameters
DH_GROUP_FOR_CREDENTIALS = "1024"  # Temporary DH for registration/login
DH_GROUP_FOR_SESSION = "2048"      # Long-lived session DH

# ============================================================================
# Logging Configuration
# ============================================================================

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "logs/client.log")
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

# ============================================================================
# UI Configuration
# ============================================================================

# Default user credentials (for testing)
DEFAULT_EMAIL = os.getenv("DEFAULT_EMAIL", "user@example.com")
DEFAULT_USERNAME = os.getenv("DEFAULT_USERNAME", "user")

# ============================================================================
# Transcript Configuration
# ============================================================================

# Directory to export transcripts
TRANSCRIPT_DIR = os.getenv("TRANSCRIPT_DIR", "transcripts")

# ============================================================================
# Utility Functions
# ============================================================================


def validate_config() -> bool:
    """
    Validate that all required configuration is present.

    Returns:
        True if valid, raises exception otherwise
    """
    required_files = [
        CLIENT_CERT_FILE,
        CLIENT_KEY_FILE,
        CA_CERT_FILE,
    ]

    for filepath in required_files:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Required file not found: {filepath}")

    return True
