#!/usr/bin/env python3
"""ClauDoor-hooks manual test and status utility."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from pathlib import Path

try:
    import yaml
    import requests
except ImportError:
    print("Missing dependencies. Run: pip install pyyaml requests")
    sys.exit(1)

CONFIG_FILE     = Path.home() / ".config" / "claudoor-hooks" / "config.yaml"
INSTALL_DIR     = Path.home() / ".local" / "share" / "claudoor-hooks"
CLAUDE_SETTINGS = Path.home() / ".claude" / "settings.json"


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        print(f"Error: config not found at {CONFIG_FILE}")
        print("Run install.py first.")
        sys.exit(1)
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f) or {}


def encrypt_payload(pubkey_b64: str, data: dict) -> str:
    try:
        from nacl.public import PublicKey, SealedBox
    except ImportError:
        print("Error: pynacl not installed. Run: pip install pynacl")
        sys.exit(1)
    pad = (4 - len(pubkey_b64) % 4) % 4
    pubkey_bytes = base64.urlsafe_b64decode(pubkey_b64 + "=" * pad)
    ciphertext = SealedBox(PublicKey(pubkey_bytes)).encrypt(
        json.dumps(data, ensure_ascii=False).encode()
    )
    return base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode()


def cmd_test_notify() -> None:
    config         = load_config()
    topic          = config.get("topic", "")
    phone_pubkey   = config.get("phone_public_key", "")
    response_topic = secrets.token_urlsafe(48)
    timeout        = int(config.get("timeout", 90))

    if not phone_pubkey:
        print("Error: phone_public_key not set. Run scripts/pair.py first.")
        sys.exit(1)

    req_id = f"test-{int(time.time())}-{os.getpid()}"
    sig    = hmac.new(topic.encode(), req_id.encode(), hashlib.sha256).hexdigest()[:16]

    encrypted = encrypt_payload(phone_pubkey, {
        "tool_name":      "Bash",
        "tool_input":     '{"command": "echo \\"ClauDoor E2E test\\""}',
        "project":        "test",
        "req_id":         req_id,
        "sig":            sig,
        "response_topic": response_topic,
    })

    print(f"Sending E2E encrypted test notification…")
    print(f"  Topic:          {topic[:24]}…")
    print(f"  Response topic: {response_topic[:24]}…")
    print("Tap Allow or Deny in the ClauDoor app.\n")

    try:
        requests.post(
            "https://ntfy.sh/",
            json={"topic": topic, "title": "ClauDoor", "message": encrypted,
                  "priority": 4, "tags": ["lock"]},
            timeout=10,
        )
    except Exception as e:
        print(f"Error sending notification: {e}")
        return

    print(f"Notification sent. Waiting for response (timeout: {timeout}s)…")

    since    = int(time.time())
    deadline = time.monotonic() + timeout
    decision = ""

    while time.monotonic() < deadline and not decision:
        time.sleep(1)
        try:
            resp = requests.get(
                f"https://ntfy.sh/{response_topic}/json",
                params={"poll": "1", "since": str(since)},
                timeout=5,
            )
            for line in resp.text.splitlines():
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                    if msg.get("time", 0) > since:
                        since = msg["time"]
                    parts = msg.get("message", "").split("|")
                    if len(parts) == 3 and parts[1] == req_id and parts[2] == sig:
                        decision = parts[0]
                        break
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

    if decision in ("allow", "deny"):
        print(f"Response received: {decision}")
        print("E2E test passed!")
    else:
        print("Timeout: no response received.")
        print("Make sure the ClauDoor app is running and paired to this topic.")


def cmd_status() -> None:
    print("=== ClauDoor-hooks status ===\n")

    # Config
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            cfg = yaml.safe_load(f) or {}
        print(f"[OK] Config:      {CONFIG_FILE}")
        print(f"     Topic:       {cfg.get('topic', '(not set)')[:32]}…")
        print(f"     Timeout:     {cfg.get('timeout', 90)}s")
        print(f"     Phone delay: {cfg.get('phone_delay', 0)}s")
        pubkey = cfg.get("phone_public_key", "")
        if pubkey:
            print(f"[OK] Pubkey:      {pubkey[:32]}…")
        else:
            print("[NG] Pubkey:      not set — run scripts/pair.py")
    else:
        print(f"[NG] Config:      not found at {CONFIG_FILE}")

    # Hook script
    hook_path = INSTALL_DIR / "hooks" / "claudoor-hooks.py"
    if hook_path.exists():
        print(f"[OK] Hook:        {hook_path}")
    else:
        print(f"[NG] Hook:        not found at {hook_path}")

    # Claude settings
    if CLAUDE_SETTINGS.exists():
        try:
            settings   = json.loads(CLAUDE_SETTINGS.read_text())
            registered = [
                h for h in settings.get("hooks", {}).get("PermissionRequest", [])
                if any(n in h.get("hooks", [{}])[0].get("command", "")
                       for n in ("claudoor-hooks", "claudoor-hooks"))
            ]
            if registered:
                print(f"[OK] Settings:    hook registered in {CLAUDE_SETTINGS}")
            else:
                print(f"[NG] Settings:    hook not found in {CLAUDE_SETTINGS}")
        except Exception:
            print(f"[NG] Settings:    could not parse {CLAUDE_SETTINGS}")
    else:
        print(f"[NG] Settings:    {CLAUDE_SETTINGS} not found")

    # Python & dependencies
    print(f"[OK] Python:      {sys.version.split()[0]} — {sys.executable}")
    for pkg in ("yaml", "requests", "nacl"):
        try:
            __import__(pkg)
            print(f"[OK] Dep:         {pkg}")
        except ImportError:
            print(f"[NG] Dep:         {pkg} not installed")


def main() -> None:
    parser = argparse.ArgumentParser(description="ClauDoor-hooks test utility")
    sub    = parser.add_subparsers(dest="command")
    sub.add_parser("test-notify", help="Send an E2E encrypted test notification and wait for response")
    sub.add_parser("status",      help="Check installation status")
    args = parser.parse_args()

    if args.command == "test-notify":
        cmd_test_notify()
    elif args.command == "status":
        cmd_status()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
