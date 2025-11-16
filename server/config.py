"""
Server Configuration Module

Manages database connections and protocol parameters for the secure chat server.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# ============================================================================
# Database Configuration
# ============================================================================

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "securechat")

# Database connection pool settings
DB_CONNECTION_TIMEOUT = 10
DB_AUTOCOMMIT = True

# ============================================================================
# Server Network Configuration
# ============================================================================

SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SERVER_PORT", 5000))
SERVER_BACKLOG = 5

# ============================================================================
# Certificate Configuration
# ============================================================================

CERT_DIR = os.getenv("CERT_DIR", "certs")
SERVER_CERT_FILE = os.path.join(CERT_DIR, "server_cert.pem")
SERVER_KEY_FILE = os.path.join(CERT_DIR, "server_private_key.pem")
CA_CERT_FILE = os.path.join(CERT_DIR, "ca_cert.pem")
CLIENT_CERT_FILE = os.path.join(CERT_DIR, "client_cert.pem")

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
LOG_FILE = os.getenv("LOG_FILE", "logs/server.log")
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

# ============================================================================
# Security Constraints
# ============================================================================

# Password hashing
PASSWORD_HASH_ALGORITHM = "SHA256"
PASSWORD_SALT_LENGTH = 16

# Never log these patterns
SENSITIVE_PATTERNS = [
    "password",
    "pwd",
    "secret",
    "key",
    "token",
    "private",
]

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
        SERVER_CERT_FILE,
        SERVER_KEY_FILE,
        CA_CERT_FILE,
    ]

    for filepath in required_files:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Required file not found: {filepath}")

    return True


def get_db_connection_params() -> dict:
    """Get database connection parameters as dictionary."""
    return {
        "host": DB_HOST,
        "port": DB_PORT,
        "user": DB_USER,
        "password": DB_PASSWORD,
        "database": DB_NAME,
        "autocommit": DB_AUTOCOMMIT,
        "connection_timeout": DB_CONNECTION_TIMEOUT,
    }
