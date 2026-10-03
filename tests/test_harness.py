"""End-to-end behaviour: request -> policy -> decision -> execution -> verification -> audit."""

from __future__ import annotations

import json

import pytest

from ai_automation_harness import (
    ApprovalStatus,
    Decision,
    ExecutionStatus,
    Harness,
    Outcome,
    ReasonCode,
    ToolRegistry,
    VerificationStatus,
    verify_chain,
)
from ai_automation_harness.errors import ApprovalError, RegistrySealedError
from ai_automation_harness.tools.demo import build_demo_registry
from ai_automation_harness.world import SimulatedWorld

from .conftest import (
    FakeClock,
    HarnessFactory,
    draft_req,
    email_policy,
    mail_req,
    make_policy,
    req,
)
from .custom_tools import (
    FAKE_SECRET,
    call,
    misbehaving_policy,
    register_misbehaving,
)


def misbehaving_harness(
    make_harness: HarnessFactory, world: SimulatedWorld | None = None
) -> Harness:
    registry = build_demo_registry()
    register_misbehaving(registry)
    return make_harness(misbehaving_policy(), registry, world)


def event_types(harness: Harness, request_id: str) -> list[str]:
    return [e.event_type for e in harness.audit.events if e.request_id == request_id]


# ------------------------------------------------------------------ the happy and gated paths


def test_allowed_read_flows_through_every_stage(harness: Harness) -> None:
    result = harness.submit(req("r1"))
    assert result.decision.decision is Decision.ALLOW
    assert result.outcome is Outcome.COMPLETED
    assert result.execution_status is ExecutionStatus.SUCCEEDED
    assert result.verification_status is VerificationStatus.VERIFIED
    assert result.output is not None and result.output["status"] == "active"
    assert event_types(harness, "r1") == [
        "policy.decision",
        "execution.finished",
        "verification.finished",
        "request.finished",
    ]
    harness.audit.verify()


def test_gated_request_waits_then_completes_after_explicit_approval(harness: Harness) -> None:
    pending = harness.submit(draft_req("d1"))
    assert pending.outcome is Outcome.PENDING_APPROVAL
    assert pending.approval_status is ApprovalStatus.PENDING
    assert pending.execution_status is ExecutionStatus.NOT_EXECUTED
    assert harness.resume("d1").outcome is Outcome.PENDING_APPROVAL  # still nothing happens
    assert pending.approval_id is not None
    harness.approve(pending.approval_id, "alice", "reviewed")
    done = harness.resume("d1")
    assert done.outcome is Outcome.COMPLETED
    assert done.approval_status is ApprovalStatus.APPROVED
    assert harness.resume("d1") == done  # idempotent once finished
    assert event_types(harness, "d1") == [
        "policy.decision",
        "approval.requested",
        "approval.approved",
        "execution.finished",
        "verification.finished",
        "request.finished",
    ]


def test_high_risk_action_without_approval_never_executes(make_harness: HarnessFactory) -> None:
    world = SimulatedWorld()
    harness = make_harness(email_policy(), world=world)
    result = harness.submit(mail_req("m1"))
    assert result.decision.decision is Decision.REQUIRE_APPROVAL
    assert result.outcome is Outcome.PENDING_APPROVAL
    assert world.reader.counters()["outbox"] == 0
    harness.resume("m1")
    assert world.reader.counters()["outbox"] == 0


def test_send_email_runs_only_after_approval_and_is_verified(make_harness: HarnessFactory) -> None:
    world = SimulatedWorld()
    harness = make_harness(email_policy(), world=world)
    pending = harness.submit(mail_req("m1"))
    assert pending.approval_id is not None
    harness.approve(pending.approval_id, "alice")
    done = harness.resume("m1")
    assert done.outcome is Outcome.COMPLETED
    assert world.reader.counters()["outbox"] == 1


def test_rejected_request_never_executes_and_is_finished_immediately(
    make_harness: HarnessFactory,
) -> None:
    world = SimulatedWorld()
    harness = make_harness(world=world)
    pending = harness.submit(draft_req("d1"))
    assert pending.approval_id is not None
    harness.reject(pending.approval_id, "alice", "not today")
    result = harness.resume("d1")
    assert result.outcome is Outcome.REJECTED
    assert result.execution_status is ExecutionStatus.NOT_EXECUTED
    assert world.reader.counters()["drafts"] == 0
    assert event_types(harness, "d1")[-2:] == ["approval.rejected", "request.finished"]


def test_expired_approval_never_executes(make_harness: HarnessFactory, clock: FakeClock) -> None:
    world = SimulatedWorld()
    harness = make_harness(world=world)
    pending = harness.submit(draft_req("d1"))
    clock.advance(901)
    result = harness.resume("d1")
    assert result.outcome is Outcome.EXPIRED
    assert result.approval_status is ApprovalStatus.EXPIRED
    assert world.reader.counters()["drafts"] == 0
    assert pending.approval_id is not None
    with pytest.raises(ApprovalError):
        harness.approve(pending.approval_id, "alice")  # too late


def test_approval_that_lapses_before_resume_is_not_honoured(
    make_harness: HarnessFactory, clock: FakeClock
) -> None:
    harness = make_harness()
    pending = harness.submit(draft_req("d1"))
    assert pending.approval_id is not None
    harness.approve(pending.approval_id, "alice")
    clock.advance(901)
    assert harness.resume("d1").outcome is Outcome.EXPIRED


def test_requester_cannot_approve_its_own_request(harness: Harness) -> None:
    pending = harness.submit(draft_req("d1", requester="agent-7"))
    assert pending.approval_id is not None
    with pytest.raises(ApprovalError):
        harness.approve(pending.approval_id, "agent-7")
    assert harness.resume("d1").outcome is Outcome.PENDING_APPROVAL


def test_unknown_request_and_approval_ids_raise(harness: Harness) -> None:
    with pytest.raises(ApprovalError):
        harness.resume("nope")
    with pytest.raises(ApprovalError):
        harness.approve("appr-nope", "alice")
    with pytest.raises(ApprovalError):
        harness.reject("appr-nope", "alice")


# ------------------------------------------------------------------ denial paths


@pytest.mark.parametrize(
    ("request_", "code"),
    [
        (req("x1", "transfer_funds", "run", "payments:write", {}), ReasonCode.UNKNOWN_TOOL),
        (req("x2", action="write"), ReasonCode.UNDECLARED_ACTION),
        (req("x3", scope="accounts:admin"), ReasonCode.SCOPE_NOT_DECLARED),
        (
            req("x4", "delete_file", "delete", "files:delete", {"path": "docs/readme.txt"}),
            ReasonCode.TOOL_DENIED,
        ),
        (mail_req("x5"), ReasonCode.TOOL_NOT_ALLOWED),
        (
            req("x6", arguments={"account_id": "acct-1001", "admin": True}),
            ReasonCode.INVALID_ARGUMENTS,
        ),
        (draft_req("x7", to="mallory@evil.test"), ReasonCode.ARGUMENT_NOT_ALLOWLISTED),
    ],
)
def test_denials_are_recorded_with_evidence_and_never_execute(
    harness: Harness, request_: object, code: ReasonCode
) -> None:
    result = harness.submit(request_)  # type: ignore[arg-type]
    assert result.decision.decision is Decision.DENY
    assert result.decision.reason_code is code
    assert result.outcome is Outcome.DENIED
    assert result.execution_status is ExecutionStatus.NOT_EXECUTED
    assert result.verification_status is VerificationStatus.NOT_RUN
    record = harness.evidence.get(result.evidence_ref)
    assert record is not None and record["policy_decision"]["reason_code"] == code.value
    assert record["execution"]["status"] == "NOT_EXECUTED"


def test_malformed_requests_are_denied_and_audited_not_raised(harness: Harness) -> None:
    for raw in ({"tool": "read_account"}, "just a string", {"request_id": "r\n1"}, None):
        result = harness.submit(raw)  # type: ignore[arg-type]
        assert result.decision.reason_code is ReasonCode.MALFORMED_REQUEST
        assert result.outcome is Outcome.DENIED
    assert len(harness.audit.events) == 8
    harness.audit.verify()


def test_request_id_replay_is_denied(harness: Harness) -> None:
    first = harness.submit(draft_req("d1"))
    replay = harness.submit(draft_req("d1", to="mallory@evil.test"))
    assert replay.decision.reason_code is ReasonCode.DUPLICATE_REQUEST_ID
    assert replay.outcome is Outcome.DENIED
    assert first.outcome is Outcome.PENDING_APPROVAL
    again = harness.submit(draft_req("d1"))
    assert again.evidence_ref != replay.evidence_ref  # each denial gets its own record


def test_policy_change_between_submit_and_resume_is_enforced(
    make_harness: HarnessFactory,
) -> None:
    """The executor re-evaluates; an approval cannot outlive a policy that now denies the tool."""
    registry = build_demo_registry()
    harness = make_harness(make_policy(), registry)
    pending = harness.submit(draft_req("d1"))
    assert pending.approval_id is not None
    harness.approve(pending.approval_id, "alice")
    # swap in a stricter policy on the same engine boundary
    stricter = make_policy(
        denied_tools=["delete_file", "create_draft"],
        allowed_tools={
            "read_account": {"scopes": ["accounts:read"]},
        },
    )
    from ai_automation_harness import PolicyEngine

    harness._executor._engine = PolicyEngine(stricter, registry)
    result = harness.resume("d1")
    assert result.outcome is Outcome.DENIED
    assert result.execution_status is ExecutionStatus.NOT_EXECUTED


# ------------------------------------------------------------------ registry bypass


def test_tools_cannot_be_added_after_the_harness_is_built(harness: Harness) -> None:
    registry = harness._registry
    assert registry.sealed
    with pytest.raises(RegistrySealedError):
        registry.register(build_demo_registry().get("read_account"), lambda ctx: {})  # type: ignore[arg-type]


def test_executor_is_the_only_path_to_a_handler(harness: Harness) -> None:
    """A denied request submitted through any public entry point never reaches a handler."""
    marker = harness._world.reader.digest()
    harness.submit(req("b1", "delete_file", "delete", "files:delete", {"path": "docs/readme.txt"}))
    harness.submit(mail_req("b2"))
    assert harness._world.reader.digest() == marker
    assert harness._world.reader.file_exists("docs/readme.txt")


def test_registry_without_checks_is_refused_when_policy_requires_verification(
    make_harness: HarnessFactory,
) -> None:
    from ai_automation_harness import ArgSpec, Risk, SideEffect, ToolSpec
    from ai_automation_harness.errors import MalformedPolicyError

    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="unchecked",
            description="No checks.",
            risk=Risk.READ,
            scopes=frozenset({"accounts:read"}),
            side_effects=SideEffect.NONE,
            allowed_actions=frozenset({"read"}),
            requires_approval=False,
            arguments={"a": ArgSpec(required=False)},
        ),
        lambda ctx: {},
    )
    with pytest.raises(MalformedPolicyError):
        make_harness(make_policy(allowed_tools={}), registry)


# ------------------------------------------------------------------ execution != verification


def test_execution_success_is_not_verification_success(make_harness: HarnessFactory) -> None:
    """The tool reports success. The environment disagrees. The outcome must say so."""
    world = SimulatedWorld(frozenset({"silent_drop_draft"}))
    harness = make_harness(world=world)
    pending = harness.submit(draft_req("d1"))
    assert pending.approval_id is not None
    harness.approve(pending.approval_id, "alice")
    result = harness.resume("d1")
    assert result.execution_status is ExecutionStatus.SUCCEEDED
    assert result.output is not None and result.output["draft_id"] == "draft-0001"
    assert result.verification_status is VerificationStatus.NOT_VERIFIED
    assert result.outcome is Outcome.EXECUTED_NOT_VERIFIED
    assert world.reader.counters()["drafts"] == 0


def test_silent_email_drop_is_not_verified(make_harness: HarnessFactory) -> None:
    harness = make_harness(email_policy(), world=SimulatedWorld(frozenset({"silent_drop_email"})))
    pending = harness.submit(mail_req("m1"))
    assert pending.approval_id is not None
    harness.approve(pending.approval_id, "alice")
    result = harness.resume("m1")
    assert result.outcome is Outcome.EXECUTED_NOT_VERIFIED


def test_unobservable_state_is_uncertain_not_failed_and_not_verified(
    make_harness: HarnessFactory,
) -> None:
    harness = make_harness(world=SimulatedWorld(frozenset({"observer_unavailable"})))
    pending = harness.submit(draft_req("d1"))
    assert pending.approval_id is not None
    harness.approve(pending.approval_id, "alice")
    result = harness.resume("d1")
    assert result.verification_status is VerificationStatus.UNCERTAIN
    assert result.outcome is Outcome.EXECUTED_UNCERTAIN
    assert result.reason.endswith("UNCERTAIN")


def test_missing_evidence_reference_is_uncertain(make_harness: HarnessFactory) -> None:
    harness = make_harness(email_policy(), world=SimulatedWorld(frozenset({"omit_receipt_ref"})))
    pending = harness.submit(mail_req("m1"))
    assert pending.approval_id is not None
    harness.approve(pending.approval_id, "alice")
    result = harness.resume("m1")
    assert result.verification is not None
    by_name = {c.name: c.status for c in result.verification.checks}
    assert by_name["message_in_outbox"] is VerificationStatus.VERIFIED
    assert by_name["evidence_exists"] is VerificationStatus.UNCERTAIN
    assert result.outcome is Outcome.EXECUTED_UNCERTAIN


def test_tool_returning_success_while_expected_state_is_absent(
    make_harness: HarnessFactory,
) -> None:
    harness = misbehaving_harness(make_harness)
    pending = harness.submit(call("f1", "fake_delete"))
    assert pending.approval_id is not None
    harness.approve(pending.approval_id, "alice")
    result = harness.resume("f1")
    assert result.execution_status is ExecutionStatus.SUCCEEDED
    assert result.outcome is Outcome.EXECUTED_NOT_VERIFIED
    assert result.verification is not None
    assert {c.name: c.status for c in result.verification.checks}["file_is_absent"] is (
        VerificationStatus.NOT_VERIFIED
    )


def test_incomplete_output_is_not_verified(make_harness: HarnessFactory) -> None:
    world = SimulatedWorld()
    harness = misbehaving_harness(make_harness, world)
    result = harness.submit(call("i1", "incomplete_output"))
    assert result.outcome is Outcome.EXECUTED_NOT_VERIFIED
    assert result.verification is not None
    assert "missing field 'receipt_ref'" in result.verification.checks[0].detail
    assert world.reader.counters()["drafts"] == 1  # the effect happened; the claim is incomplete


def test_failed_execution_with_partial_effects_is_flagged(make_harness: HarnessFactory) -> None:
    world = SimulatedWorld()
    harness = misbehaving_harness(make_harness, world)
    result = harness.submit(call("h1", "half_writer"))
    assert result.outcome is Outcome.EXECUTION_FAILED
    assert result.execution_status is ExecutionStatus.FAILED
    assert result.verification_status is VerificationStatus.NOT_VERIFIED
    record = harness.evidence.get("ev-h1")
    assert record is not None and record["flags"] == {"partial_effects_detected": True}
    assert world.reader.counters()["drafts"] == 1


def test_failed_execution_without_effects_has_no_verification(
    make_harness: HarnessFactory,
) -> None:
    harness = make_harness()
    result = harness.submit(req("r1", arguments={"account_id": "acct-9999"}))
    assert result.outcome is Outcome.EXECUTION_FAILED
    assert result.verification_status is VerificationStatus.NOT_RUN
    assert result.reason == "ToolFailure: account not found"


def test_non_mapping_handler_result_is_a_failure(make_harness: HarnessFactory) -> None:
    result = misbehaving_harness(make_harness).submit(call("l1", "returns_list"))
    assert result.outcome is Outcome.EXECUTION_FAILED


# ------------------------------------------------------------------ read-only enforcement


def test_read_only_tool_gets_no_writer_so_a_write_attempt_fails(
    make_harness: HarnessFactory,
) -> None:
    world = SimulatedWorld()
    before = world.reader.digest()
    result = misbehaving_harness(make_harness, world).submit(call("w1", "blind_writer"))
    assert result.outcome is Outcome.EXECUTION_FAILED
    assert world.reader.digest() == before


def test_read_only_tool_that_mutates_anyway_is_caught_by_the_invariant(
    make_harness: HarnessFactory,
) -> None:
    """Even a handler that bypasses its read-only view cannot report a clean result."""
    world = SimulatedWorld()
    result = misbehaving_harness(make_harness, world).submit(call("w2", "leaky_reader"))
    assert result.execution_status is ExecutionStatus.SUCCEEDED
    assert result.verification_status is VerificationStatus.NOT_VERIFIED
    assert result.outcome is Outcome.EXECUTED_NOT_VERIFIED
    assert result.verification is not None
    assert result.verification.checks[0].name == "state_unchanged"


# ------------------------------------------------------------------ secrets and evidence


def test_secrets_in_arguments_errors_and_outputs_never_reach_audit_or_evidence(
    make_harness: HarnessFactory,
) -> None:
    harness = misbehaving_harness(make_harness)
    harness.submit(call("s1", "leaks_secret_in_error"))
    harness.submit(call("s2", "echoes_secret"))
    drafted = harness.submit(
        req(
            "s3",
            "create_draft",
            "create",
            "drafts:write",
            {"to": "a@example.org", "subject": "s", "body": f"password=hunter2 {FAKE_SECRET}"},
        )
    )
    assert drafted.outcome is Outcome.COMPLETED
    blob = harness.audit.to_jsonl() + json.dumps(
        [harness.evidence.get(r) for r in harness.evidence.refs()]
    )
    assert FAKE_SECRET not in blob
    assert "hunter2" not in blob
    assert "[REDACTED]" in blob


def test_every_audit_event_carries_every_mandatory_field(harness: Harness) -> None:
    harness.submit(req("a1"))
    harness.submit(mail_req("a2"))
    pending = harness.submit(draft_req("a3"))
    assert pending.approval_id is not None
    harness.approve(pending.approval_id, "alice")
    harness.resume("a3")
    harness.submit({"nonsense": 1})
    mandatory = (
        *("timestamp", "request_id", "tool", "action", "risk", "scope", "policy_decision"),
        *("approval_status", "execution_status", "verification_status", "reason"),
        *("evidence_ref", "outcome", "reason_code"),
    )
    assert len(harness.audit.events) > 10
    for event in harness.audit.events:
        data = event.to_dict()
        for name in mandatory:
            assert data[name] not in (None, ""), (event.event_type, name)


def test_final_event_binds_the_evidence_record_by_digest(harness: Harness) -> None:
    from ai_automation_harness.evidence import evidence_digest

    result = harness.submit(req("e1"))
    final = [e for e in harness.audit.events if e.event_type == "request.finished"][-1]
    record = harness.evidence.get(result.evidence_ref)
    assert record is not None
    assert final.evidence_digest == evidence_digest(record)
    assert record["policy_sha256"] == make_policy().digest
    assert record["verification"]["status"] == "VERIFIED"


def test_evidence_export_and_audit_chain_survive_a_full_session(
    harness: Harness, tmp_path: object
) -> None:
    from pathlib import Path

    out = Path(str(tmp_path))
    harness.submit(req("e1"))
    harness.submit(mail_req("e2"))
    files = harness.evidence.export(out / "evidence")
    assert {f.name for f in files} == {"ev-e1.json", "ev-e2.json"}
    assert json.loads(files[0].read_text())["request"]["request_id"] == "e1"
    assert verify_chain(harness.audit.events) == len(harness.audit.events)


def test_hmac_keyed_harness_produces_a_verifiable_chain(make_harness: HarnessFactory) -> None:
    harness = make_harness(hmac_key=b"k" * 32)
    harness.submit(req("r1"))
    assert verify_chain(harness.audit.events, b"k" * 32) == len(harness.audit.events)
