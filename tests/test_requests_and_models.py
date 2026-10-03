from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from ai_automation_harness import Risk, SideEffect, ToolRequest
from ai_automation_harness.errors import MalformedRequestError

VALID: dict[str, Any] = {
    "request_id": "r1",
    "tool": "read_account",
    "action": "read",
    "scope": "accounts:read",
    "arguments": {"account_id": "acct-1001"},
}


def test_risk_levels_are_ordered_and_labelled() -> None:
    assert Risk.READ < Risk.LOW < Risk.MEDIUM < Risk.HIGH < Risk.CRITICAL
    assert Risk.HIGH.label == "high"
    assert Risk.parse("critical") is Risk.CRITICAL


@pytest.mark.parametrize("bad", ["CRITICAL", "extreme", "", None, 3])
def test_risk_parse_rejects_unknown_labels(bad: object) -> None:
    with pytest.raises(ValueError):
        Risk.parse(bad)


def test_side_effect_parse() -> None:
    assert SideEffect.parse("external") is SideEffect.EXTERNAL
    with pytest.raises(ValueError):
        SideEffect.parse("everything")


@pytest.mark.parametrize(
    "mutation",
    [
        {"request_id": ""},
        {"request_id": "x" * 65},
        {"request_id": "bad id with spaces"},
        {"request_id": "line\nbreak"},
        {"tool": "../etc/passwd"},
        {"action": ""},
        {"scope": "no-colon"},
        {"scope": "Accounts:Read"},
        {"arguments": ["not", "a", "mapping"]},
        {"arguments": {"nested": {"a": 1}}},
        {"arguments": {"floaty": 1.5}},
        {"arguments": {"bad key!": "x"}},
        {"arguments": {"long": "x" * 5000}},
        {"requester": "bad requester"},
        {"side_effect": "sometimes"},
        {"unexpected_field": 1},
    ],
)
def test_malformed_requests_are_rejected(mutation: dict[str, Any]) -> None:
    with pytest.raises(MalformedRequestError):
        ToolRequest.from_mapping({**VALID, **mutation})


@pytest.mark.parametrize("missing", ["request_id", "tool", "action", "scope"])
def test_missing_required_fields_are_rejected(missing: str) -> None:
    raw = {k: v for k, v in VALID.items() if k != missing}
    with pytest.raises(MalformedRequestError):
        ToolRequest.from_mapping(raw)


def test_non_mapping_request_is_rejected() -> None:
    with pytest.raises(MalformedRequestError):
        ToolRequest.from_mapping("read_account")


def test_error_messages_never_echo_values() -> None:
    secret = "hunter2-" + "x" * 10
    with pytest.raises(MalformedRequestError) as info:
        ToolRequest.from_mapping({**VALID, "request_id": secret + " bad"})
    assert secret not in str(info.value)


def test_requests_are_immutable() -> None:
    request = ToolRequest.from_mapping(VALID)
    with pytest.raises(FrozenInstanceError):
        request.tool = "delete_file"  # type: ignore[misc]
    with pytest.raises(TypeError):
        request.arguments["account_id"] = "acct-9999"  # type: ignore[index]


def test_arguments_digest_binds_exact_arguments() -> None:
    a = ToolRequest.from_mapping(VALID)
    b = ToolRequest.from_mapping({**VALID, "arguments": {"account_id": "acct-1002"}})
    assert a.arguments_digest == ToolRequest.from_mapping(VALID).arguments_digest
    assert a.arguments_digest != b.arguments_digest
