#!/usr/bin/env python3
"""ClauDoor-hooks uninstaller."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

INSTALL_DIR     = Path.home() / ".local" / "share" / "claudoor-hooks"
CONFIG_DIR      = Path.home() / ".config" / "claudoor-hooks"
CLAUDE_SETTINGS = Path.home() / ".claude" / "settings.json"


def remove_hook_from_settings() -> None:
    if not CLAUDE_SETTINGS.exists():
        print(f"Warning: {CLAUDE_SETTINGS} not found (skipped)")
        return
    try:
        settings = json.loads(CLAUDE_SETTINGS.read_text())
        entries  = settings.get("hooks", {}).get("PermissionRequest", [])
        filtered = [
            h for h in entries
            if not any(name in h.get("hooks", [{}])[0].get("command", "")
                       for name in ("claudoor-hooks", "claudoor-hooks"))
        ]
        if not filtered and entries:
            settings["hooks"].pop("PermissionRequest", None)
        else:
            settings["hooks"]["PermissionRequest"] = filtered
        CLAUDE_SETTINGS.write_text(json.dumps(settings, indent=2))
        print(f"Removed hook from {CLAUDE_SETTINGS}")
    except Exception as e:
        print(f"Warning: could not update {CLAUDE_SETTINGS}: {e}")


def remove_install_dir() -> None:
    if INSTALL_DIR.exists():
        shutil.rmtree(INSTALL_DIR)
        print(f"Removed {INSTALL_DIR}")
    else:
        print("No install directory found (skipped)")


def remove_config() -> None:
    if not CONFIG_DIR.exists():
        print("No config directory found (skipped)")
        return
    answer = input(f"Remove config at {CONFIG_DIR}? [y/N]: ").strip().lower()
    if answer == "y":
        shutil.rmtree(CONFIG_DIR)
        print(f"Removed {CONFIG_DIR}")
    else:
        print(f"Kept {CONFIG_DIR}")


def main() -> None:
    print("=== ClauDoor-hooks uninstaller ===\n")
    remove_hook_from_settings()
    remove_install_dir()
    remove_config()
    print("\n=== Uninstall complete ===")


if __name__ == "__main__":
    main()
