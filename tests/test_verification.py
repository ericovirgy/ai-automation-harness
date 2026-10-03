from __future__ import annotations

from typing import Any

from ai_automation_harness import Risk, SideEffect, ToolSpec, VerificationStatus
from ai_automation_harness.verification import (
    CheckResult,
    VerificationContext,
    evidence_exists,
    expected_state,
    invariant,
    output_schema,
    run_checks,
    state_unchanged,
)
from ai_automation_harness.world import ObservationError, SimulatedWorld

from .conftest import req

V, N, U = (
    VerificationStatus.VERIFIED,
    VerificationStatus.NOT_VERIFIED,
    VerificationStatus.UNCERTAIN,
)


def ctx_for(output: dict[str, Any], before: str = "a", after: str = "a") -> VerificationContext:
    spec = ToolSpec(
        name="sample_tool",
        description="x",
        risk=Risk.READ,
        scopes=frozenset({"a:read"}),
        side_effects=SideEffect.NONE,
        allowed_actions=frozenset({"read"}),
        requires_approval=False,
    )
    world = SimulatedWorld()
    return VerificationContext(
        req(), spec, output, world.reader, world.reader.counters(), before, after
    )


def status_of(check: Any, output: dict[str, Any], **kw: str) -> VerificationStatus:
    result: CheckResult = check(ctx_for(output, **kw))
    return result.status


def test_output_schema() -> None:
    check = output_schema({"id": str, "count": int})
    assert status_of(check, {"id": "x", "count": 2}) is V
    assert status_of(check, {"id": "x"}) is N  # missing field
    assert status_of(check, {"id": "x", "count": "2"}) is N  # wrong type
    assert status_of(check, {"id": "x", "count": True}) is N  # bool is not an int


def test_expected_state_verified_mismatch_absent_unreadable() -> None:
    def make(observed: object) -> Any:
        return expected_state("state", lambda c: observed, lambda c: "yes")

    assert status_of(make("yes"), {}) is V
    assert status_of(make("no"), {}) is N
    assert status_of(make(None), {}) is N

    def broken(_: VerificationContext) -> object:
        raise ObservationError("cannot read")

    results = run_checks([expected_state("state", broken, lambda c: "yes")], ctx_for({}))
    assert results.status is U  # cannot observe is not the same as contradicted


def test_invariant() -> None:
    assert status_of(invariant("inv", lambda c: True), {}) is V
    assert status_of(invariant("inv", lambda c: False), {}) is N


def test_evidence_exists_distinguishes_missing_reference_from_dangling_reference() -> None:
    check = evidence_exists("ref", lambda c, ref: {"ok": 1} if ref == "good" else None)
    assert status_of(check, {"ref": "good"}) is V
    assert status_of(check, {"ref": "dangling"}) is N  # points at nothing
    assert status_of(check, {}) is U  # nothing to examine
    assert status_of(check, {"ref": ""}) is U
    assert status_of(check, {"ref": 5}) is U


def test_state_unchanged() -> None:
    assert status_of(state_unchanged(), {}, before="a", after="a") is V
    assert status_of(state_unchanged(), {}, before="a", after="b") is N


def test_no_checks_is_uncertain_never_verified() -> None:
    result = run_checks([], ctx_for({}))
    assert result.status is U
    assert result.checks == ()


def test_not_verified_beats_uncertain_beats_verified() -> None:
    ok = invariant("ok", lambda c: True)
    bad = invariant("bad", lambda c: False)
    unsure = evidence_exists("ref", lambda c, r: None)
    assert run_checks([ok, ok], ctx_for({})).status is V
    assert run_checks([ok, unsure], ctx_for({})).status is U
    assert run_checks([ok, unsure, bad], ctx_for({})).status is N


def test_a_crashing_check_is_uncertain_and_its_message_is_redacted() -> None:
    def boom(_: VerificationContext) -> CheckResult:
        raise RuntimeError("token=" + "s3cr3t-value")

    result = run_checks([boom], ctx_for({}))
    assert result.status is U
    assert "s3cr3t-value" not in result.checks[0].detail
    assert result.checks[0].name == "boom"


def test_verification_result_serialises() -> None:
    data = run_checks([invariant("ok", lambda c: True)], ctx_for({})).to_dict()
    assert data["status"] == "VERIFIED"
    assert data["checks"][0]["name"] == "ok"
