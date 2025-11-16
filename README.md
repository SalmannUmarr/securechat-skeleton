# Secure Chat System

A console-based secure chat application demonstrating **CIANR** (Confidentiality, Integrity, Authenticity, Non-Repudiation) principles using cryptographic protocols.

## Features

- **Confidentiality**: AES-128-CBC encryption for messages
- **Integrity**: SHA-256 hashing with RSA-PSS digital signatures
- **Authenticity**: X.509 certificate mutual authentication with CA chain validation
- **Non-Repudiation**: Append-only transcript with signed session receipts

### Protocol Stack

| Layer | Component | Purpose |
|-------|-----------|---------|
| **Control Plane** | Certificate Exchange | Mutual TLS-like authentication |
| **Control Plane** | Temporary DH (1024-bit) | Encrypted registration/login payload |
| **Control Plane** | Session DH (2048-bit) | Derive long-lived AES key |
| **Data Plane** | Per-Message Format | seqno, timestamp, CT, signature |
| **Audit** | Transcript + Receipt | Non-repudiation evidence |

### Security Properties

- **Mutual Authentication**: Both client and server verify certificates against CA
- **Perfect Forward Secrecy**: Temporary DH for credentials; session DH derives independent key
- **Replay Detection**: Sequence number tracking and timestamp validation
- **Tamper Detection**: RSA-PSS signatures over message components (seqno\|\|ts\|\|ct)
- **Non-Repudiation**: Signed session transcript with peer certificate fingerprints

## Repository Structure

```
securechat-skeleton/
├─ scripts/
│  ├─ gen_ca.py                 # Generate Root CA
│  └─ gen_cert.py               # Issue client/server certificates
├─ certs/                        # Generated certificates (NOT committed)
│  ├─ ca_cert.pem               # Root CA public (committed)
│  ├─ ca_private_key.pem        # Root CA private (NOT committed)
│  ├─ client_cert.pem           # Client public (committed)
│  ├─ client_private_key.pem    # Client private (NOT committed)
│  ├─ server_cert.pem           # Server public (committed)
│  └─ server_private_key.pem    # Server private (NOT committed)
├─ server/
│  ├─ server.py                 # Main server implementation
│  └─ config.py                 # Server configuration
├─ client/
│  ├─ client.py                 # Main client implementation
│  └─ config.py                 # Client configuration
├─ utils/
│  ├─ crypto_utils.py           # RSA, AES, SHA-256, cert operations
│  ├─ dh.py                     # Diffie-Hellman with RFC3526 groups
│  └─ transcript.py             # Append-only transcript + receipts
├─ mysql/
│  └─ schema.sql                # MySQL database schema
├─ tests/
│  ├─ test_invalid_cert.py     # Certificate validation tests
│  ├─ test_replay_tamper.py    # Replay & tampering tests
│  └─ run_all_tests.sh          # Test runner
├─ .env.example                 # Environment template
├─ .gitignore                   # Prevent committing secrets
├─ requirements.txt             # Python dependencies
└─ README.md                    # This file
```

## Installation

### Prerequisites

- Python 3.10+
- MySQL 5.7+ (for user storage)
- pip or conda

### Setup

1. **Clone repository**

```bash
git clone https://github.com/yourusername/securechat-skeleton.git
cd securechat-skeleton
```

2. **Install dependencies**

```bash
pip install -r requirements.txt
```

3. **Configure environment**

```bash
cp .env.example .env
# Edit .env with your database and server settings
```

4. **Create MySQL database**

```bash
mysql -u root -p < mysql/schema.sql
```

## Quick Start

### Step 1: Generate CA and Certificates

```bash
# Generate Root CA
python3 scripts/gen_ca.py

# Generate client and server certificates
python3 scripts/gen_cert.py client localhost
python3 scripts/gen_cert.py server localhost
```

This creates:
- `certs/ca_cert.pem` (CA public certificate - committed)
- `certs/ca_private_key.pem` (CA private key - NOT committed)
- `certs/client_cert.pem` (Client certificate - committed)
- `certs/client_private_key.pem` (Client key - NOT committed)
- `certs/server_cert.pem` (Server certificate - committed)
- `certs/server_private_key.pem` (Server key - NOT committed)

**SECURITY**: Private keys are generated with mode 0600 (owner-only) and should never be committed to version control. `.gitignore` prevents accidental commits.

### Step 2: Start Server

```bash
python3 server/server.py
```

Output:
```
[*] Secure Chat Server listening on 0.0.0.0:5000
```

### Step 3: Run Client

In a new terminal:

```bash
python3 client/client.py
```

Interactive prompts:
1. Register new account or login
2. Enter username and password
3. Type messages to send
4. Type `quit` to exit and export transcript

### Step 4: View Transcript

Transcripts are automatically exported to `transcripts/` directory:

```
transcripts/
└─ transcript_20231115_143022.txt
```

Format:
```
seqno|ts|base64(ct)|base64(sig)|peer_cert_fingerprint
0|1700055622123|AeF1d2k/JJ8=...|sig_base64...|sha256_fp...
1|1700055622456|BfG2e3l/KK9=...|sig_base64...|sha256_fp...
```

## Protocol Details

### Control Plane: Certificate Exchange

**Client → Server:**
```json
{
  "type": "hello",
  "client_cert": "<PEM>",
  "nonce": "<base64>"
}
```

**Server → Client:**
```json
{
  "type": "server_hello",
  "server_cert": "<PEM>",
  "nonce": "<base64>"
}
```

**Validation:**
- Parse and load certificates
- Verify signature chain to CA
- Check validity period (notBefore, notAfter)
- Verify CN/hostname match
- Reject on failure with `{"type":"error","error_type":"bad-cert"}`

### Control Plane: Temporary DH (for credentials)

1. **Client initiates (1024-bit RFC3526 Group 1):**
```json
{"type":"dh_client", "g":2, "p":<big_int>, "A":<big_int>}
```

2. **Server responds:**
```json
{"type":"dh_server", "B":<big_int>}
```

3. **Both compute:**
   - Shared secret: `Ks = B^a mod p` (or `A^b mod p`)
   - AES key: `K = SHA256(Ks_bytes)[:16]`

4. **Client sends encrypted credentials:**
```json
{
  "type": "register or login",
  "payload": "<base64(iv||ciphertext)>"
}
```

Decrypted payload (register):
```json
{
  "type": "register",
  "email": "user@example.com",
  "username": "user",
  "salt": "<base64(16_bytes)>",
  "pwd": "<base64(SHA256(salt||password))>"
}
```

Decrypted payload (login):
```json
{
  "type": "login",
  "email": "user@example.com",
  "pwd": "<base64(SHA256(salt||password))>"
}
```

### Control Plane: Session DH

Uses 2048-bit RFC3526 Group 14 for long-lived session encryption.

Same exchange as temporary DH, derives session AES key: `K_session = SHA256(Ks_bytes)[:16]`

### Data Plane: Message Format

```json
{
  "type": "msg",
  "seqno": 0,
  "ts": 1700055622123,
  "ct": "<base64(iv||ciphertext)>",
  "sig": "<base64(RSA_SIGN(seqno_bytes || ts_bytes || ct))>"
}
```

**Serialization for signature:**
- `seqno_bytes`: 8-byte big-endian
- `ts_bytes`: 8-byte big-endian (unix milliseconds)
- `ct`: Raw bytes (iv || ciphertext)

**Validation:**
1. Verify RSA-PSS signature (SHA-256)
2. Check sequence number (no replays)
3. Check timestamp (< 5 minutes old)
4. Decrypt with AES-128-CBC
5. Append to transcript

**Transcript Entry:**
```
seqno|ts|base64(ct)|base64(sig)|peer_cert_fingerprint
```

### Non-Repudiation: Session Receipt

At end of session:

1. **Compute transcript hash:**
   ```
   TranscriptHash = SHA256(concat(lines with '\n'))
   ```

2. **Sign and create receipt:**
   ```json
   {
     "type": "receipt",
     "peer": "client or server",
     "created_at": "2023-11-15T14:30:22Z",
     "first_seqno": 0,
     "last_seqno": 15,
     "message_count": 16,
     "transcript_hash": "<hex(SHA256)>",
     "peer_cert_fingerprint": "<hex(SHA256(DER))>",
     "signature": "<base64(RSA_SIGN(transcript_hash))>",
     "signer_cert": "<base64(PEM)>"
   }
   ```

3. **Offline verification:**
   ```bash
   python3 -c "
   from utils.transcript import verify_transcript_receipt
   receipt = SessionReceipt.from_json_file('receipt.json')
   transcript = Transcript.import_lines('transcript.txt')
   valid, reason = verify_transcript_receipt(receipt, transcript, cert_pem)
   print('Valid' if valid else f'Invalid: {reason}')
   "
   ```

## Database Schema

```sql
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  username VARCHAR(255) UNIQUE NOT NULL,
  salt VARBINARY(16) NOT NULL,
  pwd_hash CHAR(64) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  session_token VARCHAR(64) UNIQUE NOT NULL,
  client_cert_fingerprint VARCHAR(64) NOT NULL,
  server_cert_fingerprint VARCHAR(64) NOT NULL,
  transcript_hash VARCHAR(64),
  started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  ended_at TIMESTAMP NULL,
  message_count INT DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE audit_log (
  id INT AUTO_INCREMENT PRIMARY KEY,
  event_type VARCHAR(50) NOT NULL,
  email VARCHAR(255),
  client_cert_fingerprint VARCHAR(64),
  reason VARCHAR(255),
  occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  ip_address VARCHAR(45)
);
```

## Security Implementation Details

### Password Hashing

```python
# Never stored plaintext!
salt = os.urandom(16)
pwd_hash = SHA256(salt || password)
# Store in DB: (salt, hex(pwd_hash))

# On login:
provided_pwd = input()
provided_hash = SHA256(stored_salt || provided_pwd)
# Use constant-time comparison
if compare_ct(provided_hash, stored_hash):
    # Authenticated
```

### Signature Verification

All signatures use **RSASSA-PSS** with **SHA-256**:

```python
from cryptography.hazmat.primitives.asymmetric import padding

# Sign
sig = private_key.sign(
  data,
  padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
  ),
  hashes.SHA256()
)

# Verify
public_key.verify(
  sig,
  data,
  padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
  ),
  hashes.SHA256()
)
```

### Encryption/Decryption

**AES-128-CBC with PKCS#7 padding:**

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Encrypt
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
padded_pt = plaintext + bytes([padding_len]) * padding_len
ct = encryptor.update(padded_pt) + encryptor.finalize()
return iv + ct  # Prepend IV

# Decrypt
iv = ct_with_iv[:16]
ct = ct_with_iv[16:]
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
padded_pt = decryptor.update(ct) + decryptor.finalize()
return padded_pt[:-padded_pt[-1]]  # Remove PKCS#7 padding
```

### Diffie-Hellman Parameters

Uses **RFC 3526 MODP Groups**:

- **Group 1 (1024-bit)**: Temporary DH for credentials
- **Group 14 (2048-bit)**: Session DH for message encryption

No custom group generation; uses well-vetted standard parameters.

## Testing

### Run all tests

```bash
bash tests/run_all_tests.sh
```

### Individual tests

```bash
# Test certificate validation (expired, self-signed, invalid CN)
python3 -m pytest tests/test_invalid_cert.py -v

# Test replay/tamper detection
python3 -m pytest tests/test_replay_tamper.py -v
```

### Manual protocol verification

**Wireshark Filter (verify no plaintext credentials):**

```
tcp.port == 5000 && json.value contains "password"
```

Should return **0 matches** if working correctly.

## Logging and Audit

### Server logs

```
logs/server.log
```

Entries include:
- Certificate validation
- Login success/failure
- Message receipts
- Errors (never logs plaintext passwords)

### Audit table

```sql
SELECT * FROM audit_log WHERE event_type = 'login_failure';
SELECT * FROM audit_log WHERE event_type = 'cert_invalid';
```

## Troubleshooting

### "Certificate not found"

Ensure you ran the generation scripts:

```bash
python3 scripts/gen_ca.py
python3 scripts/gen_cert.py client localhost
python3 scripts/gen_cert.py server localhost
```

### "Database connection failed"

Verify `.env` settings and MySQL is running:

```bash
mysql -u root -p -e "SELECT 1"
```

### "Certificate validation failed"

Check certificate CN matches hostname. For development with `localhost`:

```bash
openssl x509 -in certs/server_cert.pem -text | grep CN
# Should show: CN=SERVER: localhost
```

### "Permission denied" on private keys

Ensure private keys have restricted permissions:

```bash
chmod 600 certs/*_private_key.pem
```

## Compliance & Standards

- **RFC 3526**: Modular Exponential Diffie-Hellman Groups
- **FIPS 180-4**: SHA-256
- **PKCS #1 v2.2**: RSA-PSS
- **PKCS #7**: Padding
- **X.509 v3**: Certificates
- **OpenSSL/BoringSSL**: Cryptographic library (via `cryptography` package)

## Performance Considerations

- RSA key size: **2048-bit** (minimum for production)
- AES variant: **AES-128** (128-bit keys)
- DH groups: **RFC3526** (pre-computed safe primes)
- Hash: **SHA-256** (256-bit)
- Database: **MySQL** (indexed on email/username)
- Threading: **Per-client handler** (scalable to ~100 concurrent)

## Future Improvements

- [ ] Perfect Forward Secrecy (ephemeral DH per message)
- [ ] Certificate pinning
- [ ] Rate limiting on login attempts
- [ ] Key rotation protocol
- [ ] Multi-party messaging
- [ ] Persistent session store
- [ ] TLS upgrade path for production
- [ ] Hardware security module (HSM) support

## Security Warnings

⚠️ **This is an educational implementation.** For production:

1. **Use TLS/SSL** instead of raw sockets
2. **Store keys in HSM** or key management service
3. **Implement certificate revocation** (CRL/OCSP)
4. **Add rate limiting** on authentication attempts
5. **Use connection pooling** for database
6. **Enable audit logging** and monitoring
7. **Rotate certificates** regularly
8. **Use strong random number generation** (os.urandom is secure)
9. **Implement API authentication** separately
10. **Regular security audits** and penetration testing

## License

Educational use. See LICENSE file.

## Contact

For questions or issues, please open a GitHub issue.

---

**Last Updated**: November 2024  
**Python Version**: 3.10+  
**Status**: Reference Implementation
