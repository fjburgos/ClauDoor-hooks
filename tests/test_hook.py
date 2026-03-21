"""Tests for hooks/claudoor-hooks.py (E2E-only mode)."""
from __future__ import annotations

import base64
import importlib.util
import json
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

# ── Load hook module by file path ────────────────────────────────────────────
_HOOK_FILE = Path(__file__).parent.parent / "hooks" / "claudoor-hooks.py"
_spec      = importlib.util.spec_from_file_location("claude_push_hook", _HOOK_FILE)
hook       = importlib.util.module_from_spec(_spec)
sys.modules["claude_push_hook"] = hook
_spec.loader.exec_module(hook)
# ─────────────────────────────────────────────────────────────────────────────


def _gen_keypair():
    from nacl.public import PrivateKey
    priv = PrivateKey.generate()
    pub_b64 = base64.urlsafe_b64encode(bytes(priv.public_key)).rstrip(b"=").decode()
    return priv, pub_b64


# ── parse_input ───────────────────────────────────────────────────────────────

def test_parse_input_full():
    raw = json.dumps({
        "tool_name":  "Bash",
        "tool_input": {"command": "ls -la"},
        "cwd":        "/home/user/myproject",
    })
    tool_name, tool_input, project = hook.parse_input(raw)
    assert tool_name == "Bash"
    assert "command" in tool_input
    assert project == "myproject"


def test_parse_input_defaults():
    tool_name, tool_input, project = hook.parse_input("{}")
    assert tool_name == "Unknown"
    assert tool_input == "{}"
    assert project == "unknown"


def test_parse_input_invalid_json():
    tool_name, _, project = hook.parse_input("not json at all")
    assert tool_name == "Unknown"
    assert project == "unknown"


def test_parse_input_truncates_at_200():
    raw = json.dumps({"tool_input": {"data": "x" * 500}})
    _, tool_input_str, _ = hook.parse_input(raw)
    assert len(tool_input_str) <= 200


# ── compute_sig ───────────────────────────────────────────────────────────────

def test_compute_sig_is_deterministic():
    assert hook.compute_sig("topic", "req-1") == hook.compute_sig("topic", "req-1")


def test_compute_sig_differs_by_topic():
    assert hook.compute_sig("topic-a", "req-1") != hook.compute_sig("topic-b", "req-1")


def test_compute_sig_differs_by_req_id():
    assert hook.compute_sig("topic", "req-1") != hook.compute_sig("topic", "req-2")


def test_compute_sig_length():
    assert len(hook.compute_sig("topic", "req-1")) == 16


# ── encrypt_payload ───────────────────────────────────────────────────────────

def test_encrypt_payload_is_decryptable():
    from nacl.public import SealedBox
    priv, pub_b64 = _gen_keypair()
    data = {"tool_name": "Bash", "req_id": "r1", "sig": "abc"}

    ciphertext = hook.encrypt_payload(pub_b64, data)

    ct_bytes  = base64.urlsafe_b64decode(ciphertext + "==")
    plaintext = SealedBox(priv).decrypt(ct_bytes)
    assert json.loads(plaintext)["tool_name"] == "Bash"


def test_encrypt_payload_is_nondeterministic():
    """Each call produces different ciphertext (ephemeral sender keypair)."""
    _, pub_b64 = _gen_keypair()
    data = {"x": 1}
    assert hook.encrypt_payload(pub_b64, data) != hook.encrypt_payload(pub_b64, data)


# ── build_notification ────────────────────────────────────────────────────────

def test_build_notification_encrypts_payload():
    from nacl.public import SealedBox
    priv, pub_b64 = _gen_keypair()
    sig = hook.compute_sig("topic", "req-1")

    payload = hook.build_notification("topic", "resp-topic", "proj", "Bash", "ls", "req-1", sig, pub_b64)

    assert payload["topic"]    == "topic"
    assert payload["title"]    == "ClauDoor"
    assert payload["priority"] == 4
    assert "lock" in payload["tags"]
    assert "actions" not in payload  # no plaintext action buttons


def test_build_notification_ciphertext_contains_all_fields():
    """Decrypt the notification and verify all expected fields are present."""
    from nacl.public import SealedBox
    priv, pub_b64 = _gen_keypair()
    sig = hook.compute_sig("topic", "req-1")

    payload   = hook.build_notification("topic", "resp-topic", "proj", "Bash", "ls -la", "req-1", sig, pub_b64)
    ct_bytes  = base64.urlsafe_b64decode(payload["message"] + "==")
    inner     = json.loads(SealedBox(priv).decrypt(ct_bytes))

    assert inner["tool_name"]      == "Bash"
    assert inner["tool_input"]     == "ls -la"
    assert inner["project"]        == "proj"
    assert inner["req_id"]         == "req-1"
    assert inner["sig"]            == sig
    assert inner["response_topic"] == "resp-topic"


def test_build_notification_message_is_opaque_ciphertext():
    """The ntfy message must be ciphertext — not readable JSON containing plaintext fields."""
    _, pub_b64 = _gen_keypair()
    sig = hook.compute_sig("secret-topic", "req-1")

    payload = hook.build_notification("secret-topic", "resp-topic", "proj", "Bash", "rm -rf /", "req-1", sig, pub_b64)
    message = payload["message"]

    # Must not be parseable as JSON (it's base64url ciphertext)
    with pytest.raises(json.JSONDecodeError):
        json.loads(message)
    # Must not contain cleartext tool_input verbatim
    assert "rm -rf /" not in message
    # Must have encryption overhead (SealedBox adds 48 bytes → base64 longer than plaintext)
    assert len(message) > 100


# ── format_decision ───────────────────────────────────────────────────────────

def test_format_decision_allow():
    out  = hook.format_decision("allow")
    data = json.loads(out)
    assert data["hookSpecificOutput"]["decision"]["behavior"] == "allow"
    assert data["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"


def test_format_decision_deny():
    out  = hook.format_decision("deny")
    data = json.loads(out)
    assert data["hookSpecificOutput"]["decision"]["behavior"] == "deny"


def test_format_decision_empty_returns_none():
    assert hook.format_decision("") is None
    assert hook.format_decision("timeout") is None
    assert hook.format_decision("ALLOW") is None  # case-sensitive


# ── poll_response ─────────────────────────────────────────────────────────────

def _mock_response(message: str) -> MagicMock:
    msg  = {"id": "abc", "time": int(time.time()), "message": message}
    resp = MagicMock()
    resp.text = json.dumps(msg)
    return resp


_TOPIC  = "test-topic"
_REQ_ID = "req-99"
_SIG    = hook.compute_sig(_TOPIC, _REQ_ID)


@patch("requests.get")
def test_poll_finds_allow(mock_get):
    mock_get.return_value = _mock_response(f"allow|{_REQ_ID}|{_SIG}")
    assert hook.poll_response("topic-response", _REQ_ID, timeout=5, sig=_SIG) == "allow"


@patch("requests.get")
def test_poll_finds_deny(mock_get):
    mock_get.return_value = _mock_response(f"deny|{_REQ_ID}|{_SIG}")
    assert hook.poll_response("topic-response", _REQ_ID, timeout=5, sig=_SIG) == "deny"


@patch("time.sleep")
@patch("requests.get")
def test_poll_ignores_different_req_id(mock_get, mock_sleep):
    other_sig = hook.compute_sig(_TOPIC, "req-OTHER")
    mock_get.return_value = _mock_response(f"allow|req-OTHER|{other_sig}")
    assert hook.poll_response("topic-response", _REQ_ID, timeout=0.1, sig=_SIG) == ""


@patch("time.sleep")
@patch("requests.get")
def test_poll_rejects_invalid_sig(mock_get, mock_sleep):
    mock_get.return_value = _mock_response(f"allow|{_REQ_ID}|badsignature1234")
    assert hook.poll_response("topic-response", _REQ_ID, timeout=0.1, sig=_SIG) == ""


@patch("time.sleep")
@patch("requests.get", side_effect=Exception("network error"))
def test_poll_handles_network_error(mock_get, mock_sleep):
    assert hook.poll_response("topic-response", _REQ_ID, timeout=0.1, sig=_SIG) == ""


@patch("time.sleep")
@patch("requests.get")
def test_poll_handles_malformed_json(mock_get, mock_sleep):
    bad = MagicMock()
    bad.text = "not json\nalso not json"
    mock_get.return_value = bad
    assert hook.poll_response("topic-response", _REQ_ID, timeout=0.1, sig=_SIG) == ""


# ── load_config ───────────────────────────────────────────────────────────────

def test_load_config_valid(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("topic: my-topic\ntimeout: 60\n")
    config = hook.load_config(cfg_file)
    assert config["topic"]   == "my-topic"
    assert config["timeout"] == 60


def test_load_config_missing_exits(tmp_path):
    with pytest.raises(SystemExit) as exc:
        hook.load_config(tmp_path / "nonexistent.yaml")
    assert exc.value.code == 0


def test_load_config_empty_file(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("")
    config = hook.load_config(cfg_file)
    assert config == {}
