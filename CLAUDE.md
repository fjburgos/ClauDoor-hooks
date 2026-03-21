# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Setup

Python 3.14+ with venv. Dependencies managed via pip-tools (`requirements.in` → `requirements.txt`).

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

To update dependencies:
```bash
pip install pip-tools
pip-compile requirements.in   # regenerate requirements.txt
pip-sync requirements.txt
```

## Commands

```bash
# Run all tests
pytest

# Run a single test
pytest tests/test_hook.py::test_parse_input_full

# Send a test notification (requires installed config)
python scripts/test.py test-notify

# Check installation status
python scripts/test.py status

# Pair the Android app (generates QR, runs challenge-response, saves public key)
python scripts/pair.py

# Install
python install.py

# Uninstall
python uninstall.py
```

## Architecture

This project is a Claude Code `PermissionRequest` hook that routes permission prompts to a phone via ntfy.sh with E2E encryption. Requires the ClauDoor Android app (separate repo).

**Flow:**
1. Claude Code fires `PermissionRequest`, passing JSON over stdin
2. Hook reads stdin, encrypts `{tool_name, tool_input, project, req_id, sig, response_topic}` with the phone's X25519 public key (NaCl `SealedBox`)
3. Ciphertext posted to ntfy — server sees only opaque bytes
4. Android app receives via SSE, decrypts with private key, shows native Allow/Deny notification
5. App POSTs `allow|{req_id}|{sig}` to the ephemeral `response_topic`
6. Hook verifies HMAC sig, emits decision JSON to stdout

If `phone_public_key` is missing from config, the hook exits 0 (falls back to Claude Code's interactive prompt).

**Key files:**
- `hooks/claudoor-hooks.py` — the hook; copied to `~/.local/share/claudoor-hooks/hooks/` by installer
- `install.py` — creates config, installs hook, registers in `~/.claude/settings.json`
- `uninstall.py` — reverses install steps, optionally removes config
- `scripts/pair.py` — QR + challenge-response pairing with the Android app; saves `phone_public_key` to config
- `scripts/test.py` — manual test utility (`test-notify`, `status`)
- `tests/test_hook.py` — unit tests; loads hook via `importlib` (filename has no `.py` extension in install path)

**Config** (`~/.config/claudoor-hooks/config.yaml`):
- `topic` — 64-char base64url random string; ntfy topic and HMAC key
- `timeout` — seconds before falling back to terminal prompt (default 90)
- `phone_public_key` — base64url X25519 public key from Android app; required for operation
- `phone_delay` — seconds to show local a/d prompt before sending phone notification (default 0)

**Security primitives:**
- Response topic: `secrets.token_urlsafe(48)` — 64 chars, ephemeral per request
- HMAC: `HMAC-SHA256(topic, req_id)[:16]` — authenticates phone responses
- E2E: NaCl `SealedBox` — ephemeral sender keypair per message, 48-byte overhead

**Hook output format:**
```json
{"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "allow"}}}
```
Emitting nothing (exit 0) falls back to the interactive terminal prompt.

**Dedup:** identical `tool_input` seen within 5 seconds reuses the cached decision (handles pipe commands that fire multiple PermissionRequest events in rapid succession).
