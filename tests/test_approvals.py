from __future__ import annotations

import pytest

from ai_automation_harness import ApprovalStatus, Risk
from ai_automation_harness.approvals import ApprovalGate
from ai_automation_harness.errors import ApprovalError

from .conftest import FakeClock, draft_req


@pytest.fixture
def gate(clock: FakeClock) -> ApprovalGate:
    return ApprovalGate(clock, ttl_seconds=60)


def open_one(gate: ApprovalGate, rid: str = "d1") -> str:
    return gate.open(draft_req(rid, requester="agent-1"), Risk.MEDIUM).approval_id


def test_new_approval_is_pending(gate: ApprovalGate) -> None:
    aid = open_one(gate)
    assert gate.get(aid).status is ApprovalStatus.PENDING


def test_nothing_is_implicitly_approved(gate: ApprovalGate) -> None:
    aid = open_one(gate)
    with pytest.raises(ApprovalError, match="PENDING"):
        gate.consume(aid, draft_req("d1", requester="agent-1"))


def test_approved_request_can_be_consumed_exactly_once(gate: ApprovalGate) -> None:
    aid = open_one(gate)
    gate.approve(aid, "alice")
    request = draft_req("d1", requester="agent-1")
    assert gate.consume(aid, request).consumed
    with pytest.raises(ApprovalError) as info:
        gate.consume(aid, request)
    assert info.value.code == "already_consumed"


def test_rejected_approval_cannot_be_consumed_or_reversed(gate: ApprovalGate) -> None:
    aid = open_one(gate)
    gate.reject(aid, "alice")
    assert gate.get(aid).status is ApprovalStatus.REJECTED
    with pytest.raises(ApprovalError):
        gate.consume(aid, draft_req("d1", requester="agent-1"))
    with pytest.raises(ApprovalError) as info:
        gate.approve(aid, "bob")
    assert info.value.code == "not_pending"


def test_pending_approval_expires(gate: ApprovalGate, clock: FakeClock) -> None:
    aid = open_one(gate)
    clock.advance(59)
    assert gate.get(aid).status is ApprovalStatus.PENDING
    clock.advance(1)
    assert gate.get(aid).status is ApprovalStatus.EXPIRED
    with pytest.raises(ApprovalError):
        gate.approve(aid, "alice")


def test_approved_but_unused_approval_expires(gate: ApprovalGate, clock: FakeClock) -> None:
    aid = open_one(gate)
    gate.approve(aid, "alice")
    clock.advance(61)
    assert gate.get(aid).status is ApprovalStatus.EXPIRED
    with pytest.raises(ApprovalError, match="EXPIRED"):
        gate.consume(aid, draft_req("d1", requester="agent-1"))


def test_requester_cannot_approve_its_own_request(gate: ApprovalGate) -> None:
    aid = open_one(gate)
    with pytest.raises(ApprovalError) as info:
        gate.approve(aid, "agent-1")
    assert info.value.code == "self_approval"


@pytest.mark.parametrize("approver", ["", "has space", "x" * 100, None, 7])
def test_approver_must_be_a_named_identity(gate: ApprovalGate, approver: object) -> None:
    aid = open_one(gate)
    with pytest.raises(ApprovalError) as info:
        gate.approve(aid, approver)  # type: ignore[arg-type]
    assert info.value.code == "invalid_approver"


def test_approval_is_bound_to_the_exact_arguments(gate: ApprovalGate) -> None:
    aid = open_one(gate)
    gate.approve(aid, "alice")
    tampered = draft_req("d1", to="mallory@evil.test", requester="agent-1")
    with pytest.raises(ApprovalError) as info:
        gate.consume(aid, tampered)
    assert info.value.code == "mismatch"


def test_approval_cannot_be_used_for_another_tool_or_request(gate: ApprovalGate) -> None:
    aid = open_one(gate)
    gate.approve(aid, "alice")
    other = draft_req("d2", requester="agent-1")
    with pytest.raises(ApprovalError) as info:
        gate.consume(aid, other)
    assert info.value.code == "mismatch"


def test_unknown_and_duplicate_approvals(gate: ApprovalGate) -> None:
    with pytest.raises(ApprovalError):
        gate.get("appr-nope")
    open_one(gate)
    with pytest.raises(ApprovalError) as info:
        open_one(gate)
    assert info.value.code == "duplicate"


def test_approval_record_serialises_without_arguments(gate: ApprovalGate) -> None:
    aid = open_one(gate)
    gate.approve(aid, "alice", note="looks fine")
    data = gate.get(aid).to_dict()
    assert data["status"] == "APPROVED"
    assert data["decided_by"] == "alice"
    assert "arguments" not in data and "arguments_digest" not in data
