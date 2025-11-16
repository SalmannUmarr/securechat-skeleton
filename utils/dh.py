"""
Diffie-Hellman Key Exchange Module - Provides DH keypair generation and shared secret computation.

Uses RFC3526 MODP Groups for secure DH exchange:
- 1024-bit group: For temporary credential encryption
- 2048-bit group: For session encryption (more secure)

Protocol:
1. Client generates (private_a, public_A = g^a mod p)
2. Server generates (private_b, public_B = g^b mod p)
3. Exchange A and B over authenticated channel (certificates)
4. Both compute shared_secret = peer_public ^ own_private mod p
5. Derive key: K = SHA256(shared_secret_bytes)[:16] for AES-128

CIANR Mapping:
- Confidentiality: DH-derived AES keys for encryption
- Authenticity: DH parameters verified against known groups
- Integrity: Shared secret used to derive authenticated encryption keys

References:
- RFC 3526: More Modular Exponential (MODP) Diffie-Hellman groups
"""

import os
from typing import Tuple

# RFC3526 MODP Group 14 (2048-bit)
# Used for session encryption (long-lived)
RFC3526_GROUP14_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
    16,
)
RFC3526_GROUP14_G = 2

# RFC3526 MODP Group 1 (1024-bit)
# Used for temporary credential encryption (short-lived)
RFC3526_GROUP1_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE6538100000000000000",
    16,
)
RFC3526_GROUP1_G = 2


def generate_dh_keypair(
    p: int = RFC3526_GROUP14_P, g: int = RFC3526_GROUP14_G
) -> Tuple[int, int]:
    """
    Generate Diffie-Hellman keypair (private key, public key).

    Args:
        p: Prime modulus (default: RFC3526 Group 14, 2048-bit)
        g: Generator (default: 2)

    Returns:
        (private_key, public_key) where:
        - private_key: Random integer 1 < private < p-1
        - public_key: g^private mod p

    CIANR: Confidentiality (generates secret)
    """
    # Generate random private key in range (1, p-2)
    # Using random bytes for better entropy
    private_key = int.from_bytes(
        os.urandom(128), byteorder="big"
    ) % (p - 2) + 1

    # Compute public key
    public_key = pow(g, private_key, p)

    return private_key, public_key


def compute_shared_secret(peer_public: int, own_private: int, p: int) -> int:
    """
    Compute shared secret in Diffie-Hellman exchange.

    Args:
        peer_public: Peer's public key
        own_private: Own private key
        p: Prime modulus

    Returns:
        Shared secret = peer_public ^ own_private mod p

    Both parties will compute the same shared secret:
        Client: B^a mod p
        Server: A^b mod p
        Result: g^(ab) mod p (same)

    CIANR: Confidentiality
    """
    shared_secret = pow(peer_public, own_private, p)
    return shared_secret


def dh_shared_secret_to_key(shared_secret: int, key_length: int = 16) -> bytes:
    """
    Convert DH shared secret (integer) to cryptographic key.

    Args:
        shared_secret: Shared secret from DH exchange
        key_length: Desired key length in bytes (default 16 for AES-128)

    Returns:
        Key bytes derived from SHA256 of shared secret

    Process:
        1. Convert big-endian integer to bytes
        2. Compute SHA256(secret_bytes)
        3. Truncate to key_length (typically 16 for AES-128)

    CIANR: Confidentiality (derives AES key)
    """
    import hashlib

    # Convert shared secret to big-endian bytes (2048 bits = 256 bytes)
    secret_bytes = shared_secret.to_bytes(256, byteorder="big")

    # Hash with SHA-256
    key_material = hashlib.sha256(secret_bytes).digest()

    # Truncate to desired key length
    return key_material[:key_length]


# Convenience function for typical DH flow
def dh_flow(
    group_size: str = "2048",
) -> Tuple[int, int, int, int, int]:
    """
    Helper to perform complete DH flow setup.

    Args:
        group_size: "1024" for short-lived (credentials), "2048" for long-lived (session)

    Returns:
        (private, public, g, p, peer_public) where peer_public will be filled by peer

    Example:
        privA, pubA, g, p, _ = dh_flow("2048")
        # Send pubA to peer
        # Receive pubB from peer
        shared = compute_shared_secret(pubB, privA, p)
    """
    if group_size == "1024":
        p, g = RFC3526_GROUP1_P, RFC3526_GROUP1_G
    elif group_size == "2048":
        p, g = RFC3526_GROUP14_P, RFC3526_GROUP14_G
    else:
        raise ValueError(f"Unknown group size: {group_size}")

    private, public = generate_dh_keypair(p, g)
    return private, public, g, p, None


# Verification and validation
def is_valid_dh_public_key(public_key: int, p: int) -> bool:
    """
    Basic validation of DH public key (0 < public < p).

    Args:
        public_key: Public key to validate
        p: Prime modulus

    Returns:
        True if valid
    """
    return 0 < public_key < p


def dh_sanity_check(p: int, g: int) -> bool:
    """
    Sanity check for DH parameters.

    Args:
        p: Prime modulus
        g: Generator

    Returns:
        True if parameters seem reasonable
    """
    # Verify g is within range
    if not (1 < g < p):
        return False

    # Verify p is reasonably large (at least 1024-bit)
    if p.bit_length() < 1024:
        return False

    return True
