#!/usr/bin/env python3
"""ClauDoor-hooks installer — sets up ntfy.sh push notifications for Claude Code."""
from __future__ import annotations

import json
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

# Ensure dependencies are available before importing them
try:
    import yaml
except ImportError:
    print("Installing dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml>=6.0"])
    import yaml

INSTALL_DIR     = Path.home() / ".local" / "share" / "claudoor-hooks"
CONFIG_DIR      = Path.home() / ".config" / "claudoor-hooks"
CONFIG_FILE     = CONFIG_DIR / "config.yaml"
CLAUDE_SETTINGS = Path.home() / ".claude" / "settings.json"
SCRIPT_DIR      = Path(__file__).parent


def generate_topic() -> str:
    return secrets.token_urlsafe(48)


def ensure_config() -> dict:
    """Load existing config or create one by asking the user for each parameter."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            config = yaml.safe_load(f) or {}
        print(f"Config found at {CONFIG_FILE} (topic: {config.get('topic', '?')})")
        updated = False
        if "phone_delay" not in config:
            raw = input("Seconds to wait locally before notifying phone [0]: ").strip()
            config["phone_delay"] = int(raw) if raw.isdigit() else 0
            updated = True
        if updated:
            with open(CONFIG_FILE, "w") as f:
                yaml.dump(config, f, default_flow_style=False)
            print("Config updated.")
        return config

    default_topic = generate_topic()
    print("No config found. Let's create one.\n")

    raw_topic = input(f"ntfy topic [{default_topic[:24]}…]: ").strip()
    topic = raw_topic if raw_topic else default_topic

    raw_timeout = input("Response timeout in seconds [90]: ").strip()
    timeout = int(raw_timeout) if raw_timeout.isdigit() else 90

    raw_delay = input("Seconds to wait locally before notifying phone [0]: ").strip()
    phone_delay = int(raw_delay) if raw_delay.isdigit() else 0

    config = {"topic": topic, "timeout": timeout, "phone_delay": phone_delay}
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(config, f, default_flow_style=False)
    print(f"\nConfig saved to {CONFIG_FILE}")
    return config


def install_hook() -> Path:
    hook_dst = INSTALL_DIR / "hooks" / "claudoor-hooks.py"
    hook_dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(SCRIPT_DIR / "hooks" / "claudoor-hooks.py", hook_dst)
    hook_dst.chmod(0o755)
    print(f"Hook installed to {hook_dst}")
    return hook_dst


def register_hook(hook_path: Path) -> None:
    hook_cmd = f'"{sys.executable}" "{hook_path}"'

    CLAUDE_SETTINGS.parent.mkdir(parents=True, exist_ok=True)
    if not CLAUDE_SETTINGS.exists():
        CLAUDE_SETTINGS.write_text("{}")

    settings = json.loads(CLAUDE_SETTINGS.read_text())
    settings.setdefault("hooks", {})
    settings["hooks"].setdefault("PermissionRequest", [])

    # Remove any existing ClauDoor hook entries (current and legacy name)
    def _is_claudoor(h: dict) -> bool:
        cmd = h.get("hooks", [{}])[0].get("command", "")
        return "claudoor-hooks" in cmd or "claudoor-hooks" in cmd

    settings["hooks"]["PermissionRequest"] = [
        h for h in settings["hooks"]["PermissionRequest"]
        if not _is_claudoor(h)
    ]

    settings["hooks"]["PermissionRequest"].append({
        "matcher": "",
        "hooks": [{"type": "command", "command": hook_cmd, "timeout": 120}],
    })

    CLAUDE_SETTINGS.write_text(json.dumps(settings, indent=2))
    print(f"Hook registered in {CLAUDE_SETTINGS}")


def main() -> None:
    print("=== ClauDoor-hooks installer ===")
    print(f"Python {sys.version.split()[0]} — {sys.executable}")
    print()

    # Config (auto-created if missing)
    config = ensure_config()

    # Install hook
    hook_path = install_hook()

    # Register in Claude settings
    register_hook(hook_path)

    print("\n=== Installation complete ===\n")

    # Pairing is required — E2E is the only mode
    if not config.get("phone_public_key"):
        print("E2E pairing with the ClauDoor Android app is required.")
        answer = input("Pair now? [Y/n]: ").strip().lower()
        if answer in ("", "y", "yes"):
            subprocess.run([sys.executable, str(SCRIPT_DIR / "scripts" / "pair.py")])
        else:
            print("Run  python scripts/pair.py  when ready to pair.")
    else:
        print("Already paired. Run  python scripts/test.py test-notify  to verify.")


if __name__ == "__main__":
    main()
