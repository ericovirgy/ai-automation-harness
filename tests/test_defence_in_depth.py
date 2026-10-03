"""Backstops that only matter if an upstream control is bypassed (found by mutation testing)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from ai_automation_harness import (
    AuditEvent,
    Decision,
    Policy,
    PolicyEngine,
    ReasonCode,
    Risk,
    SideEffect,
    ToolSpec,
    verify_chain,
)
from ai_automation_harness.audit import GENESIS_HASH, _compute_hash
from ai_automation_harness.errors import AuditIntegrityError, ToolDeclarationError
from ai_automation_harness.tools.demo import build_demo_registry

from .conftest import policy_dict, req
from .test_audit import filled_log


@pytest.mark.parametrize("risk", [Risk.HIGH, Risk.CRITICAL])
def test_high_or_critical_risk_must_declare_requires_approval(risk: Risk) -> None:
    with pytest.raises(ToolDeclarationError, match="requires approval"):
        ToolSpec(
            name="risky_tool",
            description="Isolates the approval rule from the side-effect rules.",
            risk=risk,
            scopes=frozenset({"things:write"}),
            side_effects=SideEffect.INTERNAL,
            allowed_actions=frozenset({"apply"}),
            requires_approval=False,
        )


def test_external_side_effect_forces_approval_even_if_the_spec_was_tampered() -> None:
    registry = build_demo_registry()
    spec = registry.get("send_email")
    assert spec is not None
    object.__setattr__(spec, "requires_approval", False)
    object.__setattr__(spec, "risk", Risk.LOW)
    data = policy_dict(risk={"max_auto_risk": "medium", "max_risk": "high"})
    data["allowed_scopes"].append("email:send")
    data["allowed_tools"]["send_email"] = {"scopes": ["email:send"]}
    request = req(
        "m1",
        "send_email",
        "send",
        "email:send",
        {"to": "a@example.org", "subject": "s", "body": "b"},
    )
    decision = PolicyEngine(Policy.from_mapping(data), registry).evaluate(request)
    assert decision.decision is Decision.REQUIRE_APPROVAL
    assert decision.reason_code is ReasonCode.APPROVAL_EXTERNAL_SIDE_EFFECT


def test_critical_risk_forces_approval_even_if_the_spec_was_tampered() -> None:
    registry = build_demo_registry()
    spec = registry.get("delete_file")
    assert spec is not None
    object.__setattr__(spec, "requires_approval", False)
    data = policy_dict(risk={"max_auto_risk": "medium", "max_risk": "critical"}, denied_tools=[])
    data["allowed_scopes"].append("files:delete")
    data["allowed_tools"]["delete_file"] = {"scopes": ["files:delete"]}
    request = req("d1", "delete_file", "delete", "files:delete", {"path": "docs/readme.txt"})
    decision = PolicyEngine(Policy.from_mapping(data), registry).evaluate(request)
    assert decision.decision is Decision.REQUIRE_APPROVAL
    assert decision.reason_code is ReasonCode.APPROVAL_CRITICAL_RISK


def _reseal(event: AuditEvent) -> AuditEvent:
    return replace(event, hash=_compute_hash(replace(event, hash=""), None))


def test_broken_prev_hash_link_is_detected_even_when_each_event_hash_is_valid() -> None:
    """Models an attacker who recomputes hashes without a key but cannot fix the links."""
    events = list(filled_log().events)
    events[2] = _reseal(replace(events[2], prev_hash="f" * 64))
    with pytest.raises(AuditIntegrityError, match="broken chain link"):
        verify_chain(events)


def test_first_event_must_chain_from_genesis() -> None:
    events = list(filled_log().events)
    events[0] = _reseal(replace(events[0], prev_hash="f" * 64))
    assert events[0].prev_hash != GENESIS_HASH
    with pytest.raises(AuditIntegrityError, match="broken chain link"):
        verify_chain(events)
