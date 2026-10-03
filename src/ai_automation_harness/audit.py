"""Audit events with a hash chain. Every event carries every mandatory field."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, fields, replace
from datetime import datetime
from pathlib import Path
from typing import Any

from ai_automation_harness.errors import AuditIntegrityError
from ai_automation_harness.models import (
    ApprovalStatus,
    Decision,
    ExecutionStatus,
    Outcome,
    Risk,
    VerificationStatus,
    canonical_json,
)
from ai_automation_harness.redaction import redact

GENESIS_HASH = "0" * 64
_HASH_RE = re.compile(r"[0-9a-f]{64}")
_VALID_RISK = {r.label for r in Risk} | {"unknown"}


@dataclass(frozen=True)
class AuditEvent:
    """Every field below is required (no defaults), so a producer cannot silently omit one.

    `prev_hash` and `hash` are filled in by `AuditLog.append`.
    """

    seq: int
    timestamp: str
    request_id: str
    event_type: str
    tool: str
    action: str
    risk: str
    scope: str
    policy_decision: str
    reason_code: str
    reason: str
    approval_status: str
    execution_status: str
    verification_status: str
    outcome: str
    evidence_ref: str
    evidence_digest: str | None
    arguments: Mapping[str, Any]
    prev_hash: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["arguments"] = dict(self.arguments)
        return data

    @classmethod
    def from_dict(cls, raw: object) -> AuditEvent:
        if not isinstance(raw, Mapping):
            raise AuditIntegrityError("audit event must be an object")
        expected = {f.name for f in fields(cls)}
        missing = sorted(expected - set(raw))
        extra = sorted(set(raw) - expected)
        if missing or extra:
            raise AuditIntegrityError(
                f"audit event fields mismatch: missing={missing} extra={extra}"
            )
        event = cls(**{name: raw[name] for name in expected})
        event.validate()
        return event

    def validate(self) -> None:
        text_fields = (
            "timestamp", "request_id", "event_type", "tool", "action", "scope",
            "reason_code", "reason", "evidence_ref", "prev_hash", "hash",
        )  # fmt: skip
        for name in text_fields:
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise AuditIntegrityError(f"audit field '{name}' is missing or empty")
        for name in ("prev_hash", "hash"):
            value = getattr(self, name)
            if value != "pending" and not _HASH_RE.fullmatch(value):
                raise AuditIntegrityError(f"audit field '{name}' is not a SHA-256 hex digest")
        if isinstance(self.seq, bool) or not isinstance(self.seq, int) or self.seq < 0:
            raise AuditIntegrityError("audit field 'seq' must be a non-negative int")
        enums: tuple[tuple[str, type[Any] | set[str]], ...] = (
            ("policy_decision", Decision),
            ("approval_status", ApprovalStatus),
            ("execution_status", ExecutionStatus),
            ("verification_status", VerificationStatus),
            ("outcome", Outcome),
            ("risk", _VALID_RISK),
        )
        for name, domain in enums:
            value = getattr(self, name)
            allowed = domain if isinstance(domain, set) else {m.value for m in domain}
            if not isinstance(value, str) or value not in allowed:
                raise AuditIntegrityError(f"audit field '{name}' has an invalid value")
        if self.evidence_digest is not None and not isinstance(self.evidence_digest, str):
            raise AuditIntegrityError("audit field 'evidence_digest' must be a string or null")
        if not isinstance(self.arguments, Mapping):
            raise AuditIntegrityError("audit field 'arguments' must be an object")
        try:
            datetime.fromisoformat(self.timestamp)
        except ValueError as exc:
            raise AuditIntegrityError("audit field 'timestamp' is not ISO 8601") from exc


def _compute_hash(event: AuditEvent, key: bytes | None) -> str:
    body = event.to_dict()
    body.pop("hash")
    payload = canonical_json(body).encode("utf-8")
    if key is None:
        return hashlib.sha256(payload).hexdigest()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


class AuditLog:
    """Append-only in memory. Optional HMAC key makes the chain unforgeable without the key.

    Without an externally anchored head hash, a party able to rewrite the whole file can
    recompute a plain SHA-256 chain; truncation of the tail is likewise only detectable
    against a previously recorded `head_hash`.
    """

    def __init__(self, hmac_key: bytes | None = None) -> None:
        self._key = hmac_key
        self._events: list[AuditEvent] = []

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    @property
    def head_hash(self) -> str:
        return self._events[-1].hash if self._events else GENESIS_HASH

    def append(self, event: AuditEvent) -> AuditEvent:
        """Validate, redact free text, chain and store the event."""
        prepared = replace(
            event,
            seq=len(self._events),
            prev_hash=self.head_hash,
            hash="pending",
            reason=redact(event.reason),
            arguments=redact(event.arguments),
        )
        prepared.validate()
        sealed = replace(prepared, hash=_compute_hash(prepared, self._key))
        self._events.append(sealed)
        return sealed

    def to_jsonl(self) -> str:
        return "".join(canonical_json(e.to_dict()) + "\n" for e in self._events)

    def write_jsonl(self, path: str | Path) -> None:
        Path(path).write_text(self.to_jsonl(), encoding="utf-8")

    def verify(self) -> None:
        verify_chain(self._events, self._key)


def verify_chain(events: Iterable[AuditEvent], hmac_key: bytes | None = None) -> int:
    """Raise AuditIntegrityError on any gap, reorder, edit or malformed event."""
    prev = GENESIS_HASH
    count = 0
    for index, event in enumerate(events):
        event.validate()
        if event.seq != index:
            raise AuditIntegrityError(f"sequence gap or reorder at position {index}")
        if event.prev_hash != prev:
            raise AuditIntegrityError(f"broken chain link at event {index}")
        if not hmac.compare_digest(event.hash, _compute_hash(event, hmac_key)):
            raise AuditIntegrityError(f"hash mismatch at event {index}")
        prev = event.hash
        count += 1
    return count


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuditIntegrityError("audit line contains a duplicate key")
        result[key] = value
    return result


def load_jsonl(path: str | Path) -> list[AuditEvent]:
    """Load a log. Lines must be in canonical form so every parser reads the same content."""
    events: list[AuditEvent] = []
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise AuditIntegrityError(f"cannot read audit file: {exc.strerror}") from exc
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = AuditEvent.from_dict(json.loads(line, object_pairs_hook=_no_duplicate_keys))
        except (ValueError, TypeError, RecursionError) as exc:
            if isinstance(exc, AuditIntegrityError):
                raise
            raise AuditIntegrityError(f"line {number} is not valid audit JSON") from exc
        if canonical_json(event.to_dict()) != line.strip():
            raise AuditIntegrityError(f"line {number} is not in canonical form")
        events.append(event)
    return events
