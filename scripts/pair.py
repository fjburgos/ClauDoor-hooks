#!/usr/bin/env python3
"""Pair the Android app with the hook via QR + challenge-response.

Flow:
  1. Shows a QR in the terminal containing the ntfy topic.
  2. App scans QR, publishes its X25519 public key to {topic}-s.
  3. This script encrypts a random nonce with that pubkey (NaCl SealedBox)
     and posts the ciphertext to {topic}-c.
  4. App decrypts the nonce with its private key and posts it back to {topic}-v.
  5. If the nonce matches, the pubkey is genuine → saved to config.yaml.

Usage: python scripts/pair.py
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
from pathlib import Path

try:
    import yaml
    import requests
    import qrcode
    from nacl.public import PublicKey, SealedBox
except ImportError as e:
    print(f"Missing dependency: {e}. Run: pip install pyyaml requests qrcode pynacl")
    sys.exit(1)

CONFIG_FILE = Path.home() / ".config" / "claudoor-hooks" / "config.yaml"
NTFY_URL    = "https://ntfy.sh"
TIMEOUT     = 120  # seconds per step


def subtopic(base: str, suffix: str) -> str:
    """Derive a subtopic that stays within ntfy's 64-char limit."""
    return f"{base[:63 - len(suffix)]}-{suffix}"


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        print(f"Config not found at {CONFIG_FILE}. Run install.py first.")
        sys.exit(1)
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f) or {}


def save_pubkey(pubkey: str) -> None:
    config = load_config()
    config["phone_public_key"] = pubkey
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(config, f, default_flow_style=False)


def ntfy_post(topic: str, message: str) -> None:
    requests.post(f"{NTFY_URL}/{topic}", data=message.encode(), timeout=10)


def poll_message(topic: str, timeout: int) -> str | None:
    since    = int(time.time())
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(2)
        try:
            resp = requests.get(
                f"{NTFY_URL}/{topic}/json",
                params={"poll": "1", "since": str(since)},
                timeout=5,
            )
            for line in resp.text.splitlines():
                if not line.strip():
                    continue
                msg  = json.loads(line)
                text = msg.get("message", "").strip()
                if text:
                    return text
        except Exception:
            pass
    return None


def main() -> None:
    config = load_config()
    topic  = config.get("topic")
    if not topic:
        print("Topic not set in config. Run install.py first.")
        sys.exit(1)

    st = subtopic(topic, "s")   # setup   — app publishes pubkey here
    ct = subtopic(topic, "c")   # challenge — hook publishes encrypted nonce
    vt = subtopic(topic, "v")   # verify  — app publishes decrypted nonce

    payload = f"claudoor://pair?topic={topic}&url={NTFY_URL}"

    print("\n=== ClauDoor-hooks pairing ===\n")
    print("Scan this QR with the Claude Push Android app:\n")
    qr = qrcode.QRCode(border=1)
    qr.add_data(payload)
    qr.make(fit=True)
    qr.print_ascii(invert=True)
    print(f"  Topic: {topic}\n")

    # ── Step 1: receive public key ────────────────────────────────────────────
    print("[1/3] Waiting for app to send its public key…")
    pubkey_b64 = poll_message(st, TIMEOUT)
    if not pubkey_b64 or len(pubkey_b64) < 43:
        print("Timeout: no public key received.")
        sys.exit(1)
    print(f"      Received: {pubkey_b64[:24]}…")

    # ── Step 2: encrypt a random nonce with the received pubkey ───────────────
    print("[2/3] Sending encrypted challenge…")
    nonce      = os.urandom(32)
    nonce_b64  = base64.urlsafe_b64encode(nonce).rstrip(b"=").decode()
    pad        = (4 - len(pubkey_b64) % 4) % 4
    pubkey_bytes = base64.urlsafe_b64decode(pubkey_b64 + "=" * pad)
    ciphertext = SealedBox(PublicKey(pubkey_bytes)).encrypt(nonce)
    cipher_b64 = base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode()
    ntfy_post(ct, cipher_b64)

    # ── Step 3: verify app decrypted correctly ────────────────────────────────
    print("[3/3] Waiting for app to verify…")
    response = poll_message(vt, TIMEOUT)
    if response == nonce_b64:
        save_pubkey(pubkey_b64)
        print(f"\nPaired successfully!")
        print(f"  Public key: {pubkey_b64[:32]}…")
        print(f"  Saved to:   {CONFIG_FILE}")
        print("\nE2E encryption is now active.")
    else:
        print("\nVerification failed: app did not decrypt the challenge correctly.")
        print("The public key has NOT been saved.")
        sys.exit(1)


if __name__ == "__main__":
    main()
