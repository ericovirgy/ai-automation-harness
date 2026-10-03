from __future__ import annotations

import pytest

from ai_automation_harness import ApprovalStatus, Decision, ExecutionStatus, PolicyEngine
from ai_automation_harness.approvals import ApprovalGate
from ai_automation_harness.errors import ExecutionRefusedError
from ai_automation_harness.execution import Executor
from ai_automation_harness.tools.demo import build_demo_registry
from ai_automation_harness.world import SimulatedWorld

from .conftest import FakeClock, draft_req, mail_req, make_policy, req


class CountingWorld(SimulatedWorld):
    """Counts every time a writer is requested, i.e. every time a write-capable tool is run."""

    def __init__(self) -> None:
        super().__init__()
        self.writer_requests = 0

    @property
    def writer(self):  # type: ignore[no-untyped-def]
        self.writer_requests += 1
        return super().writer


@pytest.fixture
def parts(clock: FakeClock) -> tuple[Executor, ApprovalGate, CountingWorld]:
    registry = build_demo_registry()
    registry.seal()
    policy = make_policy()
    gate = ApprovalGate(clock, policy.approval_ttl_seconds)
    world = CountingWorld()
    return Executor(registry, PolicyEngine(policy, registry), gate, world), gate, world


def test_executor_runs_allowed_requests(
    parts: tuple[Executor, ApprovalGate, CountingWorld],
) -> None:
    executor, _, _ = parts
    record = executor.execute(req())
    assert record.status is ExecutionStatus.SUCCEEDED
    assert record.decision.decision is Decision.ALLOW
    assert record.output is not None and record.output["owner"] == "Acme"


@pytest.mark.parametrize(
    "request_",
    [
        req("u1", "transfer_funds", "run", "payments:write", {}),
        req("u2", action="write"),
        req("u3", scope="accounts:admin"),
        req("u4", "delete_file", "delete", "files:delete", {"path": "docs/readme.txt"}),
        mail_req("u5"),
    ],
)
def test_executor_refuses_denied_requests_and_never_touches_the_world(
    parts: tuple[Executor, ApprovalGate, CountingWorld], request_: object
) -> None:
    executor, _, world = parts
    before = world.reader.digest()
    with pytest.raises(ExecutionRefusedError):
        executor.execute(request_)  # type: ignore[arg-type]
    assert world.reader.digest() == before
    assert world.writer_requests == 0


def test_approval_gated_request_cannot_run_without_an_approval(
    parts: tuple[Executor, ApprovalGate, CountingWorld],
) -> None:
    executor, _, world = parts
    with pytest.raises(ExecutionRefusedError) as info:
        executor.execute(draft_req())
    assert info.value.code == "approval_pending"
    assert world.writer_requests == 0


def test_forged_or_unknown_approval_ids_are_refused(
    parts: tuple[Executor, ApprovalGate, CountingWorld],
) -> None:
    executor, gate, world = parts
    with pytest.raises(ExecutionRefusedError):
        executor.execute(draft_req(), "appr-forged")
    request = draft_req("d1", requester="agent")
    gate.open(request, make_policy().max_auto_risk)  # opened but never approved
    with pytest.raises(ExecutionRefusedError):
        executor.execute(request, "appr-d1")
    assert world.writer_requests == 0


def test_approval_is_spent_by_execution(
    parts: tuple[Executor, ApprovalGate, CountingWorld],
) -> None:
    executor, gate, _ = parts
    request = draft_req("d1", requester="agent")
    approval = gate.open(request, make_policy().max_auto_risk)
    gate.approve(approval.approval_id, "alice")
    record = executor.execute(request, approval.approval_id)
    assert record.status is ExecutionStatus.SUCCEEDED
    assert record.approval is not None and record.approval.status is ApprovalStatus.APPROVED
    with pytest.raises(ExecutionRefusedError):  # replay
        executor.execute(request, approval.approval_id)


def test_approval_for_other_arguments_cannot_be_replayed(
    parts: tuple[Executor, ApprovalGate, CountingWorld],
) -> None:
    executor, gate, world = parts
    original = draft_req("d1", requester="agent")
    approval = gate.open(original, make_policy().max_auto_risk)
    gate.approve(approval.approval_id, "alice")
    tampered = draft_req("d1", to="bob@example.org", requester="agent")
    with pytest.raises(ExecutionRefusedError):
        executor.execute(tampered, approval.approval_id)
    assert world.writer_requests == 0
