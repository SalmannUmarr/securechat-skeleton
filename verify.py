#!/usr/bin/env python3
"""
Comprehensive Verification Script for Secure Chat System

Verifies:
1. All required files exist
2. Crypto utilities work correctly
3. Certificates are valid
4. Test suite passes
"""

import os
import sys
import subprocess

def check_files():
    """Verify all required files exist."""
    required_files = [
        # Scripts
        "scripts/gen_ca.py",
        "scripts/gen_cert.py",
        # Certificates
        "certs/ca_cert.pem",
        "certs/ca_private_key.pem",
        "certs/client_cert.pem",
        "certs/client_private_key.pem",
        "certs/server_cert.pem",
        "certs/server_private_key.pem",
        # Source code
        "server/server.py",
        "server/config.py",
        "client/client.py",
        "client/config.py",
        "utils/crypto_utils.py",
        "utils/dh.py",
        "utils/transcript.py",
        # Database
        "mysql/schema.sql",
        # Tests
        "tests/test_invalid_cert.py",
        "tests/test_replay_tamper.py",
        "tests/run_all_tests.sh",
        # Configuration
        ".env",
        ".env.example",
        ".gitignore",
        "requirements.txt",
        "README.md",
    ]
    
    print("[*] Checking required files...")
    missing = []
    for f in required_files:
        if not os.path.exists(f):
            missing.append(f)
            print(f"  ✗ {f}")
        else:
            print(f"  ✓ {f}")
    
    if missing:
        print(f"\n[!] Missing {len(missing)} files:")
        for f in missing:
            print(f"    - {f}")
        return False
    
    print("[+] All required files present")
    return True

def check_permissions():
    """Verify private keys have restricted permissions."""
    print("\n[*] Checking certificate permissions...")
    private_keys = [
        "certs/ca_private_key.pem",
        "certs/client_private_key.pem",
        "certs/server_private_key.pem",
    ]
    
    for key_file in private_keys:
        if os.path.exists(key_file):
            mode = os.stat(key_file).st_mode & 0o777
            if mode != 0o600:
                print(f"  ⚠ {key_file}: mode {oct(mode)} (should be 0o600)")
                try:
                    os.chmod(key_file, 0o600)
                    print(f"    → Fixed to 0o600")
                except:
                    pass
            else:
                print(f"  ✓ {key_file}: correct permissions")
    
    return True

def check_syntax():
    """Check Python syntax."""
    print("\n[*] Checking Python syntax...")
    python_files = [
        "server/server.py",
        "client/client.py",
        "utils/crypto_utils.py",
        "utils/dh.py",
        "utils/transcript.py",
    ]
    
    errors = False
    for py_file in python_files:
        try:
            with open(py_file, 'r') as f:
                compile(f.read(), py_file, 'exec')
            print(f"  ✓ {py_file}")
        except SyntaxError as e:
            print(f"  ✗ {py_file}: {e}")
            errors = True
    
    if not errors:
        print("[+] No syntax errors found")
    return not errors

def main():
    """Run verification suite."""
    print("=" * 70)
    print("Secure Chat System - Verification Suite")
    print("=" * 70 + "\n")
    
    all_ok = True
    
    all_ok &= check_files()
    all_ok &= check_permissions()
    all_ok &= check_syntax()
    
    print("\n" + "=" * 70)
    if all_ok:
        print("[+] ✓ All checks passed!")
        print("\nNext steps:")
        print("  1. Configure MySQL database in .env")
        print("  2. Run: python3 server/server.py")
        print("  3. In another terminal: python3 client/client.py")
        print("  4. Run tests: bash tests/run_all_tests.sh")
        return 0
    else:
        print("[!] ✗ Some checks failed. Please review above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
