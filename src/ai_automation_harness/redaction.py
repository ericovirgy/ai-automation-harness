"""Redaction of secrets before anything reaches an audit event or evidence record."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"
MAX_STRING = 512
_TRUNCATED = "...[truncated]"

_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "authorization",
    "credential",
    "cookie",
    "private_key",
    "bearer",
    "session",
    "auth",
)

_VALUE_PATTERNS = (
    re.compile(r"sk[-_](?:live_|test_)?[A-Za-z0-9_-]{16,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(r"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z_-]{30,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
    re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s/]+@"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
)
# "Authorization: Basic abc", "Authorization: Bearer abc": scheme and credential go together.
_AUTH_HEADER = re.compile(
    r"(?i)(authorization\s*[=:]\s*)[\"']?[A-Za-z][A-Za-z0-9_-]*\s+[^\s\"',;]+"
)
# key=value, key: value, "key": "value". The key may be a suffix of a longer name
# (access_token, client_secret) so no word boundary is required before it.
_INLINE_ASSIGNMENT = re.compile(
    r"(?i)([A-Za-z0-9_-]*(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|authorization)"
    r"[A-Za-z0-9_-]*[\"']?\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def redact_string(text: str) -> str:
    for pattern in _VALUE_PATTERNS:
        text = pattern.sub(REDACTED, text)
    text = _AUTH_HEADER.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    text = _INLINE_ASSIGNMENT.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    if len(text) > MAX_STRING:
        text = text[:MAX_STRING] + _TRUNCATED
    return text


def redact(value: Any) -> Any:
    """Return a JSON-safe copy of `value` with secrets removed. Unknown types are stringified."""
    if isinstance(value, Mapping):
        return {
            str(k): REDACTED if is_sensitive_key(str(k)) else redact(v) for k, v in value.items()
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [redact(v) for v in value]
    if isinstance(value, bool) or value is None or isinstance(value, int | float):
        return value
    if isinstance(value, str):
        return redact_string(value)
    return redact_string(str(value))
