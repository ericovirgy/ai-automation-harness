from __future__ import annotations

from ai_automation_harness.redaction import MAX_STRING, REDACTED, redact, redact_string

# Built at runtime so static secret scanners do not mistake test fixtures for real credentials.
FAKE_OPENAI = "sk" + "-" + "a" * 32
FAKE_GITHUB = "gh" + "p_" + "b" * 36
FAKE_AWS = "AKIA" + "C" * 16
FAKE_JWT = ".".join(["eyJ" + "d" * 12, "e" * 14, "f" * 10])


def test_sensitive_keys_are_redacted_regardless_of_value() -> None:
    data = {
        "password": "hunter2",
        "API_KEY": "x",
        "auth_token": "y",
        "Authorization": "Basic zzz",
        "client_secret": "q",
        "cookie": "c",
        "nested": {"private_key": "k", "safe": "ok"},
    }
    out = redact(data)
    assert out["password"] == out["API_KEY"] == out["auth_token"] == REDACTED
    assert out["Authorization"] == out["client_secret"] == out["cookie"] == REDACTED
    assert out["nested"] == {"private_key": REDACTED, "safe": "ok"}


def test_secret_shaped_values_are_redacted_inside_free_text() -> None:
    for secret in (FAKE_OPENAI, FAKE_GITHUB, FAKE_AWS, FAKE_JWT, "Bearer abcdefghijkl"):
        text = f"before {secret} after"
        out = redact_string(text)
        assert secret not in out
        assert out.startswith("before ") and out.endswith(" after")


def test_inline_assignments_keep_the_key_but_drop_the_value() -> None:
    out = redact_string("connect with password=hunter2 and api_key: abc123def")
    assert "hunter2" not in out and "abc123def" not in out
    assert "password=" in out


def test_private_key_blocks_are_redacted() -> None:
    block = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB\n-----END RSA PRIVATE KEY-----"
    assert "MIIB" not in redact_string(f"key: {block}")


def test_long_strings_are_truncated_and_odd_types_are_stringified() -> None:
    assert len(redact("x" * 5000)) <= MAX_STRING + 20
    assert redact(range(3)) == "range(0, 3)"
    assert redact([1, ("a", None), True]) == [1, ["a", None], True]
    assert redact({"a": {1, 2}})["a"] in ([1, 2], [2, 1])
