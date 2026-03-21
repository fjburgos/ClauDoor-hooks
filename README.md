<img src="ClauDoor.webp" width="120">

# ClauDoor-hooks

Mobile push notifications for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) permission requests via [ntfy.sh](https://ntfy.sh), with E2E encryption.

When Claude Code needs permission to run a tool, you get a push notification on your phone with **Allow** / **Deny** buttons. Tap to respond — no need to stay at your terminal.

The notification payload is encrypted with your phone's public key before leaving your machine. The ntfy server only sees ciphertext.

## How It Works

```
Claude Code (PermissionRequest hook)
  → payload encrypted with phone's X25519 public key
    → posted to ntfy.sh (server sees only ciphertext)
      → ClauDoor Android app decrypts, shows Allow/Deny notification
        → response sent back via ntfy
          → hook verifies HMAC, Claude Code proceeds (or stops)
```

Uses Claude Code's [hooks system](https://docs.anthropic.com/en/docs/claude-code/hooks) (`PermissionRequest` event).

## Requirements

- Python 3.14+
- Android phone with the [ClauDoor Android app](https://github.com/fjburgos/ClauDoor-android)

## Install

```bash
git clone https://github.com/fjburgos/ClauDoor-hooks.git
cd ClauDoor-hooks
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python install.py
```

The installer creates `~/.config/claudoor-hooks/config.yaml`, installs the hook and registers it in `~/.claude/settings.json`.

## Setup

### 1. Build and install the Android app

See [ClauDoor-android](https://github.com/fjburgos/ClauDoor-android) for build and install instructions.

### 2. Pair the app with the hook

```bash
python scripts/pair.py
```

This displays a QR code in the terminal. Scan it with the ClauDoor app to complete a challenge-response exchange that saves the phone's public key to `~/.config/claudoor-hooks/config.yaml`. E2E mode activates immediately — no restart needed.

### 3. Test

```bash
python scripts/test.py test-notify   # sends a test notification and waits for your tap
python scripts/test.py status        # checks hook, config and dependencies
```

## Configuration

`~/.config/claudoor-hooks/config.yaml`:

```yaml
topic: "<64-char base64url string>"  # ntfy topic — keep private; also the HMAC key
timeout: 90                           # seconds before falling back to terminal prompt
phone_public_key: "<base64url X25519 pubkey>"  # from the Android app
phone_delay: 0                        # seconds to wait for local a/d input before notifying phone
```

Changes take effect immediately (no reinstall needed).

## Usage

Just use Claude Code normally. When a permission request triggers:

- **Allow** — Claude Code proceeds
- **Deny** — Claude Code cancels
- **Timeout** (default 90s) — falls back to the interactive terminal prompt

## Security

| | Value |
|---|---|
| Transport | HTTPS (TLS) |
| ntfy server sees | ciphertext only |
| Encryption | NaCl SealedBox (X25519 + XSalsa20-Poly1305) |
| Forward secrecy | ephemeral sender keypair per notification |
| Response auth | HMAC-SHA256(topic, req\_id) |
| Response topic | random 64-char per request |
| Private key storage | Android Keystore (TEE) |

The ntfy topic also serves as the HMAC key for response authentication — keep it private. For self-hosted ntfy with access control, see [ntfy.sh access control](https://docs.ntfy.sh/config/#access-control).

## Uninstall

```bash
python uninstall.py
```

Removes the hook from Claude settings, installed files, and optionally the config.

## Development

Dependencies are managed with [pip-tools](https://pip-tools.readthedocs.io/). Edit `requirements.in` and regenerate:

```bash
pip install pip-tools
pip-compile requirements.in
pip-sync requirements.txt
```

```bash
pytest        # run all tests
```

## Credits

Inspired by [konsti-web/claude_push](https://github.com/konsti-web/claude_push) (Windows/PowerShell + keystroke injection). This repo uses Python + the `PermissionRequest` hook for a cross-platform, E2E encrypted implementation.

## License

MIT
