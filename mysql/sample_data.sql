-- Sample data for Secure Chat System
-- Insert a test user with email test@example.com and password "password123"

-- Generate salt and compute hash:
-- salt = os.urandom(16) = (16 random bytes)
-- pwd_hash = SHA256(salt || "password123")

INSERT INTO users (email, username, salt, pwd_hash) VALUES (
    'test@example.com',
    'testuser',
    0x4d2b5a9c1f7e3a8d6c2f5b4a9e1d3f7c,
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'  -- SHA256(salt||password)
);

-- Note: These hashes are example values. To generate correct hashes:
-- 1. Generate a 16-byte random salt
-- 2. Compute SHA256(salt_bytes + password_bytes)
-- 3. Convert both to appropriate format for database

-- Example Python code to generate:
-- import os, hashlib
-- salt = os.urandom(16)
-- password = "password123"
-- pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
-- print(f"salt_hex: {salt.hex()}")
-- print(f"pwd_hash: {pwd_hash}")
-- Then use in INSERT statement above
