#!/bin/bash
# Test Runner Script - Runs all test suites

set -e

echo "[*] Secure Chat Test Suite"
echo ""

# Check if certificates exist
if [ ! -f "certs/ca_cert.pem" ]; then
    echo "[!] Certificates not found. Generating..."
    python3 scripts/gen_ca.py
    python3 scripts/gen_cert.py client localhost
    python3 scripts/gen_cert.py server localhost
fi

echo ""
echo "[*] Running test_invalid_cert.py..."
python3 -m pytest tests/test_invalid_cert.py -v

echo ""
echo "[*] Running test_replay_tamper.py..."
python3 -m pytest tests/test_replay_tamper.py -v

echo ""
echo "[+] All tests completed"
