from __future__ import annotations

import json
from dataclasses import fields, replace
from pathlib import Path
from typing import Any

import pytest

from ai_automation_harness import AuditEvent, AuditLog, verify_chain
from ai_automation_harness.audit import GENESIS_HASH, load_jsonl
from ai_automation_harness.errors import AuditIntegrityError

FAKE_OPENAI = "sk" + "-" + "a" * 32


def event(request_id: str = "r1", **overrides: Any) -> AuditEvent:
    base: dict[str, Any] = {
        "seq": 0,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "request_id": request_id,
        "event_type": "policy.decision",
        "tool": "read_account",
        "action": "read",
        "risk": "read",
        "scope": "accounts:read",
        "policy_decision": "ALLOW",
        "reason_code": "allowed_by_policy",
        "reason": "Allowed by policy",
        "approval_status": "NOT_REQUIRED",
        "execution_status": "NOT_EXECUTED",
        "verification_status": "NOT_RUN",
        "outcome": "IN_PROGRESS",
        "evidence_ref": f"ev-{request_id}",
        "evidence_digest": None,
        "arguments": {"account_id": "acct-1001"},
        "prev_hash": "",
        "hash": "",
    }
    base.update(overrides)
    return AuditEvent(**base)


def filled_log(n: int = 4, key: bytes | None = None) -> AuditLog:
    log = AuditLog(key)
    for i in range(n):
        log.append(event(f"r{i}"))
    return log


# ------------------------------------------------------------------ mandatory fields


def test_event_cannot_be_constructed_without_every_mandatory_field() -> None:
    names = [f.name for f in fields(AuditEvent)]
    full: dict[str, Any] = event().to_dict()
    for name in names:
        partial = {k: v for k, v in full.items() if k != name}
        with pytest.raises(TypeError):
            AuditEvent(**partial)


def test_loading_an_event_with_a_missing_or_extra_field_fails() -> None:
    full = event().to_dict()
    for name in ("policy_decision", "verification_status", "approval_status", "evidence_ref"):
        with pytest.raises(AuditIntegrityError):
            AuditEvent.from_dict({k: v for k, v in full.items() if k != name})
    with pytest.raises(AuditIntegrityError):
        AuditEvent.from_dict({**full, "surprise": 1})
    with pytest.raises(AuditIntegrityError):
        AuditEvent.from_dict(["not", "a", "dict"])


@pytest.mark.parametrize(
    "overrides",
    [
        {"policy_decision": "MAYBE"},
        {"approval_status": ""},
        {"execution_status": "WORKED"},
        {"verification_status": "PROBABLY"},
        {"outcome": "FINE"},
        {"risk": "extreme"},
        {"reason": ""},
        {"tool": ""},
        {"evidence_ref": ""},
        {"timestamp": "yesterday"},
        {"evidence_digest": 5},
        {"arguments": "not a mapping"},
    ],
)
def test_log_refuses_invalid_or_empty_mandatory_values(overrides: dict[str, Any]) -> None:
    with pytest.raises(AuditIntegrityError):
        AuditLog().append(event(**overrides))


@pytest.mark.parametrize("seq", [-1, True, "0"])
def test_loading_an_event_with_an_invalid_seq_fails(seq: object) -> None:
    with pytest.raises(AuditIntegrityError):
        AuditEvent.from_dict({**event().to_dict(), "seq": seq})


def test_unknown_risk_is_a_legal_explicit_value() -> None:
    AuditLog().append(event(risk="unknown"))


# ------------------------------------------------------------------ hash chain


def test_chain_links_and_verifies() -> None:
    log = filled_log()
    assert verify_chain(log.events) == 4
    assert log.events[0].prev_hash == GENESIS_HASH
    assert log.events[1].prev_hash == log.events[0].hash
    assert log.head_hash == log.events[-1].hash
    log.verify()


def test_empty_log_is_valid() -> None:
    assert verify_chain([]) == 0
    assert AuditLog().head_hash == GENESIS_HASH


def test_editing_an_event_breaks_the_chain() -> None:
    events = list(filled_log().events)
    events[1] = replace(events[1], policy_decision="DENY")
    with pytest.raises(AuditIntegrityError, match="hash mismatch"):
        verify_chain(events)


def test_deleting_an_event_breaks_the_chain() -> None:
    events = list(filled_log().events)
    del events[1]
    with pytest.raises(AuditIntegrityError):
        verify_chain(events)


def test_reordering_events_breaks_the_chain() -> None:
    events = list(filled_log().events)
    events[1], events[2] = events[2], events[1]
    with pytest.raises(AuditIntegrityError):
        verify_chain(events)


def test_rewriting_one_event_and_its_hash_still_breaks_following_links() -> None:
    log = filled_log()
    events = list(log.events)
    forged = replace(events[1], reason="rewritten")
    forged = replace(forged, hash="0" * 64)
    events[1] = forged
    with pytest.raises(AuditIntegrityError):
        verify_chain(events)


def test_truncation_is_detectable_against_an_anchored_head() -> None:
    log = filled_log()
    anchored_head = log.head_hash
    truncated = list(log.events)[:-1]
    assert verify_chain(truncated) == 3  # a bare chain cannot notice tail truncation...
    assert truncated[-1].hash != anchored_head  # ...but an externally recorded head does


def test_hmac_key_prevents_recomputing_the_chain_without_the_key() -> None:
    log = filled_log(key=b"k" * 32)
    assert verify_chain(log.events, b"k" * 32) == 4
    with pytest.raises(AuditIntegrityError):
        verify_chain(log.events, b"wrong-key" * 4)
    with pytest.raises(AuditIntegrityError):
        verify_chain(log.events)  # plain SHA-256 verification must not accept an HMAC chain


# ------------------------------------------------------------------ export


def test_jsonl_round_trip(tmp_path: Path) -> None:
    log = filled_log()
    path = tmp_path / "audit.jsonl"
    log.write_jsonl(path)
    lines = path.read_text().splitlines()
    assert len(lines) == 4
    assert all(json.loads(line)["request_id"].startswith("r") for line in lines)
    loaded = load_jsonl(path)
    assert verify_chain(loaded) == 4
    assert [e.hash for e in loaded] == [e.hash for e in log.events]


def test_load_jsonl_rejects_garbage_and_missing_files(tmp_path: Path) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{not json}\n")
    with pytest.raises(AuditIntegrityError):
        load_jsonl(bad)
    with pytest.raises(AuditIntegrityError):
        load_jsonl(tmp_path / "missing.jsonl")
    blank = tmp_path / "blank.jsonl"
    blank.write_text("\n\n")
    assert load_jsonl(blank) == []


def test_tampered_file_fails_verification(tmp_path: Path) -> None:
    log = filled_log()
    path = tmp_path / "audit.jsonl"
    log.write_jsonl(path)
    path.write_text(path.read_text().replace('"ALLOW"', '"DENY"', 1))
    with pytest.raises(AuditIntegrityError):
        verify_chain(load_jsonl(path))


# ------------------------------------------------------------------ secrets


def test_secrets_never_reach_the_log() -> None:
    log = AuditLog()
    log.append(
        event(
            reason=f"failed with token={FAKE_OPENAI} and {FAKE_OPENAI}",
            arguments={"password": "hunter2", "note": f"key {FAKE_OPENAI}", "ok": "visible"},
        )
    )
    exported = log.to_jsonl()
    assert "hunter2" not in exported
    assert FAKE_OPENAI not in exported
    assert "visible" in exported
