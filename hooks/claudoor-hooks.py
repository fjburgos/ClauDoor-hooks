#!/usr/bin/env python3
"""Claude Code PermissionRequest hook — E2E encrypted ntfy.sh push notification.

Payload is encrypted with NaCl SealedBox (X25519 + XSalsa20-Poly1305) using the
phone's public key. The ntfy server sees only opaque ciphertext. Requires the
ClauDoor Android app. Run scripts/pair.py to set up.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile
import threading
import time
from pathlib import Path

try:
    import yaml
    import requests
except ImportError:
    print("ClauDoor-hooks: missing dependencies. Run: pip install pyyaml requests", file=sys.stderr)
    sys.exit(0)

CONFIG_PATH = Path.home() / ".config" / "claudoor-hooks" / "config.yaml"


def load_config(path: Path = CONFIG_PATH) -> dict:
    if not path.exists():
        print(f"ClauDoor-hooks: config not found at {path}", file=sys.stderr)
        print("ClauDoor-hooks: run install.py to set up, falling back to interactive prompt", file=sys.stderr)
        sys.exit(0)
    with open(path) as f:
        return yaml.safe_load(f) or {}


def parse_input(raw: str) -> tuple[str, str, str]:
    """Parse Claude Code's stdin JSON. Returns (tool_name, tool_input_str, project)."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return "Unknown", "{}", "unknown"

    tool_name      = data.get("tool_name") or "Unknown"
    tool_input     = data.get("tool_input") or {}
    tool_input_str = json.dumps(tool_input, ensure_ascii=False)[:200]
    cwd            = data.get("cwd") or ""
    project        = Path(cwd).name if cwd else "unknown"

    return tool_name, tool_input_str, project


def compute_sig(topic: str, req_id: str) -> str:
    """HMAC-SHA256 signature (16 hex chars) over req_id keyed by topic."""
    return hmac.new(topic.encode(), req_id.encode(), hashlib.sha256).hexdigest()[:16]


def encrypt_payload(pubkey_b64: str, data: dict) -> str:
    """Encrypt data with phone's X25519 public key using NaCl SealedBox.

    SealedBox uses an ephemeral sender keypair per message (forward secrecy).
    Returns base64url ciphertext without padding.
    """
    try:
        from nacl.public import PublicKey, SealedBox
    except ImportError:
        print("ClauDoor-hooks: pynacl not installed. Run: pip install pynacl", file=sys.stderr)
        sys.exit(0)

    pad = (4 - len(pubkey_b64) % 4) % 4
    pubkey_bytes = base64.urlsafe_b64decode(pubkey_b64 + "=" * pad)
    box = SealedBox(PublicKey(pubkey_bytes))
    ciphertext = box.encrypt(json.dumps(data, ensure_ascii=False).encode())
    return base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode()


def build_notification(topic: str, response_topic: str, project: str,
                        tool_name: str, tool_input: str, req_id: str, sig: str,
                        phone_pubkey: str) -> dict:
    """Build an E2E encrypted ntfy notification. The Android app handles Allow/Deny."""
    encrypted = encrypt_payload(phone_pubkey, {
        "tool_name":      tool_name,
        "tool_input":     tool_input,
        "project":        project,
        "req_id":         req_id,
        "sig":            sig,
        "response_topic": response_topic,
    })
    return {
        "topic":    topic,
        "title":    "ClauDoor",
        "message":  encrypted,
        "priority": 4,
        "tags":     ["lock"],
    }


def send_notification(payload: dict) -> None:
    try:
        requests.post("https://ntfy.sh/", json=payload, timeout=10)
    except Exception:
        pass


def poll_response(response_topic: str, req_id: str, timeout: int, sig: str) -> str:
    """Poll ntfy.sh until a matching Allow/Deny response arrives. Returns 'allow', 'deny', or ''."""
    since    = int(time.time())
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
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
                        return parts[0] if parts[0] in ("allow", "deny") else ""
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

    return ""


def format_decision(decision: str) -> str | None:
    if decision in ("allow", "deny"):
        return json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {"behavior": decision},
            }
        })
    return None


DEDUP_TTL = 5  # seconds — pipe commands arrive within ~1s of each other
DEDUP_FILE = Path(tempfile.gettempdir()) / "claudoor-hooks-dedup.json"


def check_dedup(tool_input: str) -> str | None:
    """Return cached decision if the same tool_input was seen within DEDUP_TTL seconds."""
    try:
        if DEDUP_FILE.exists():
            entry = json.loads(DEDUP_FILE.read_text())
            if time.time() - entry["ts"] < DEDUP_TTL and entry["key"] == tool_input:
                return entry["decision"]
    except Exception:
        pass
    return None


def save_dedup(tool_input: str, decision: str) -> None:
    try:
        DEDUP_FILE.write_text(json.dumps({"key": tool_input, "ts": time.time(), "decision": decision}))
    except Exception:
        pass


def ask_locally(prompt: str, timeout_secs: int) -> str:
    """Show a local prompt and wait up to timeout_secs for a/d input. Returns 'allow', 'deny', or ''.

    Opens the terminal directly because sys.stdin is already consumed by the hook JSON input.
    """
    result: list[str] = []

    def _read() -> None:
        try:
            tty_path = "CONIN$" if sys.platform == "win32" else "/dev/tty"
            with open(tty_path) as tty:
                sys.stderr.write(prompt)
                sys.stderr.flush()
                line = tty.readline().strip().lower()
                if line.startswith("a"):
                    result.append("allow")
                elif line.startswith("d"):
                    result.append("deny")
        except Exception:
            pass

    t = threading.Thread(target=_read, daemon=True)
    t.start()
    t.join(timeout=timeout_secs)
    return result[0] if result else ""


def main() -> None:
    config = load_config()

    topic = config.get("topic")
    if not topic:
        print("ClauDoor-hooks: topic not set in config", file=sys.stderr)
        sys.exit(0)

    phone_pubkey = config.get("phone_public_key")
    if not phone_pubkey:
        print("ClauDoor-hooks: phone_public_key not set — run scripts/pair.py to pair the Android app", file=sys.stderr)
        sys.exit(0)

    response_topic = secrets.token_urlsafe(48)
    timeout       = int(config.get("timeout", 90))
    phone_delay   = int(config.get("phone_delay", 0))

    raw_input = sys.stdin.read()
    tool_name, tool_input, project = parse_input(raw_input)

    req_id = f"{int(time.time())}-{os.getpid()}"
    sig    = compute_sig(topic, req_id)

    # Local prompt first if phone_delay > 0
    if phone_delay > 0:
        prompt = (
            f"\n[Claude Push] [{project}] {tool_name}\n"
            f"  {tool_input}\n"
            f"Allow? [a/d] (sending to phone in {phone_delay}s): "
        )
        decision = ask_locally(prompt, phone_delay)
        if decision:
            output = format_decision(decision)
            if output:
                print(output)
            return
        sys.stderr.write("\nClauDoor-hooks: no local response, notifying phone…\n")
        sys.stderr.flush()

    payload = build_notification(topic, response_topic, project, tool_name, tool_input, req_id, sig, phone_pubkey)
    send_notification(payload)

    decision = poll_response(response_topic, req_id, timeout, sig)
    if decision:
        save_dedup(tool_input, decision)
    output = format_decision(decision)
    if output:
        print(output)
    # No output → exit 0 → Claude Code falls back to interactive prompt


if __name__ == "__main__":
    main()
