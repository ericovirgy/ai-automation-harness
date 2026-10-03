"""Execution layer: the single chokepoint through which a tool handler can run.

The executor does not accept a decision from its caller. It evaluates policy itself, so a
forged or stale "ALLOW" cannot reach a handler.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ai_automation_harness.approvals import ApprovalGate, ApprovalRecord
from ai_automation_harness.errors import ApprovalError, ExecutionRefusedError
from ai_automation_harness.models import (
    Decision,
    ExecutionStatus,
    PolicyDecision,
    ReasonCode,
    ToolRequest,
)
from ai_automation_harness.policy import PolicyEngine
from ai_automation_harness.redaction import redact_string
from ai_automation_harness.registry import ToolContext, ToolRegistry
from ai_automation_harness.world import SimulatedWorld


@dataclass(frozen=True)
class ExecutionRecord:
    status: ExecutionStatus
    decision: PolicyDecision
    approval: ApprovalRecord | None
    output: Mapping[str, Any] | None
    error: str | None
    before_digest: str
    after_digest: str
    before_counters: Mapping[str, int]


class Executor:
    def __init__(
        self,
        registry: ToolRegistry,
        engine: PolicyEngine,
        gate: ApprovalGate,
        world: SimulatedWorld,
    ) -> None:
        self._registry = registry
        self._engine = engine
        self._gate = gate
        self._world = world

    def execute(self, request: ToolRequest, approval_id: str | None = None) -> ExecutionRecord:
        decision = self._engine.evaluate(request)
        approval: ApprovalRecord | None = None
        if decision.decision is Decision.DENY:
            raise ExecutionRefusedError(decision.reason_code.value, decision.reason)
        if decision.decision is Decision.REQUIRE_APPROVAL:
            if approval_id is None:
                raise ExecutionRefusedError(
                    ReasonCode.APPROVAL_PENDING.value, "approval is required"
                )
            try:
                approval = self._gate.consume(approval_id, request)
            except ApprovalError as exc:
                raise ExecutionRefusedError(ReasonCode.APPROVAL_INVALID.value, str(exc)) from exc

        entry = self._registry._entry(request.tool)
        if entry is None:  # unreachable after a non-DENY decision; kept as defence in depth
            raise ExecutionRefusedError(ReasonCode.UNKNOWN_TOOL.value, "tool is not registered")

        reader = self._world.reader
        before_digest = reader.digest()
        before_counters = reader.counters()
        ctx = ToolContext(
            request=request,
            reader=reader,
            writer=self._world.writer if entry.spec.has_side_effects else None,
        )
        status = ExecutionStatus.SUCCEEDED
        output: Mapping[str, Any] | None = None
        error: str | None = None
        try:
            result = entry.handler(ctx)
            if not isinstance(result, Mapping):
                status, error = ExecutionStatus.FAILED, "handler returned a non-mapping result"
            else:
                output = copy.deepcopy(dict(result))
        except Exception as exc:
            status = ExecutionStatus.FAILED
            error = f"{type(exc).__name__}: {redact_string(str(exc))}"
        return ExecutionRecord(
            status=status,
            decision=decision,
            approval=approval,
            output=output,
            error=error,
            before_digest=before_digest,
            after_digest=reader.digest(),
            before_counters=before_counters,
        )
