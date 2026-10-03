"""Orchestration: request -> policy -> decision -> (approval) -> execution -> verification -> audit.

Every stage emits an audit event that snapshots the full request state, so no event can omit
the decision, approval, execution or verification fields.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ai_automation_harness.approvals import ApprovalGate, Clock, system_clock
from ai_automation_harness.audit import AuditEvent, AuditLog
from ai_automation_harness.errors import (
    ApprovalError,
    ExecutionRefusedError,
    InvariantError,
    MalformedRequestError,
)
from ai_automation_harness.evidence import EvidenceStore
from ai_automation_harness.execution import ExecutionRecord, Executor
from ai_automation_harness.models import (
    ApprovalStatus,
    Decision,
    ExecutionStatus,
    Outcome,
    PolicyDecision,
    ReasonCode,
    ToolRequest,
    VerificationStatus,
)
from ai_automation_harness.policy import Policy, PolicyEngine
from ai_automation_harness.redaction import redact, redact_string
from ai_automation_harness.registry import ToolRegistry
from ai_automation_harness.verification import (
    VerificationContext,
    VerificationResult,
    run_checks,
    state_unchanged,
)
from ai_automation_harness.world import SimulatedWorld

_APPROVAL_RESOLUTIONS = {
    ApprovalStatus.APPROVED: (ReasonCode.APPROVAL_GRANTED, "Approval granted by {by}"),
    ApprovalStatus.REJECTED: (ReasonCode.APPROVAL_REJECTED, "Approval rejected by {by}"),
    ApprovalStatus.EXPIRED: (ReasonCode.APPROVAL_EXPIRED, "Approval expired before it was used"),
}


def _required[T](value: T | None, what: str) -> T:
    if value is None:
        raise InvariantError(f"missing {what}")
    return value


@dataclass(frozen=True)
class HarnessResult:
    request_id: str
    decision: PolicyDecision
    outcome: Outcome
    approval_id: str | None
    approval_status: ApprovalStatus
    execution_status: ExecutionStatus
    verification: VerificationResult | None
    output: Mapping[str, Any] | None
    evidence_ref: str
    reason: str

    @property
    def verification_status(self) -> VerificationStatus:
        return self.verification.status if self.verification else VerificationStatus.NOT_RUN


@dataclass
class _RequestState:
    request: ToolRequest
    decision: PolicyDecision
    evidence_ref: str
    approval_id: str | None = None
    approval_status: ApprovalStatus = ApprovalStatus.NOT_REQUIRED
    logged_approval_status: ApprovalStatus = ApprovalStatus.NOT_REQUIRED
    execution_status: ExecutionStatus = ExecutionStatus.NOT_EXECUTED
    verification: VerificationResult | None = None
    execution: ExecutionRecord | None = None
    outcome: Outcome = Outcome.IN_PROGRESS
    reason_code: ReasonCode = ReasonCode.MALFORMED_REQUEST
    reason: str = ""
    finished: bool = False
    extras: dict[str, Any] = field(default_factory=dict)


class Harness:
    def __init__(
        self,
        registry: ToolRegistry,
        policy: Policy,
        world: SimulatedWorld,
        *,
        clock: Clock = system_clock,
        hmac_key: bytes | None = None,
        audit: AuditLog | None = None,
        evidence: EvidenceStore | None = None,
    ) -> None:
        registry.seal()
        self._registry = registry
        self._clock = clock
        self._world = world
        self._policy = policy
        self._engine = PolicyEngine(policy, registry)
        self._gate = ApprovalGate(clock, policy.approval_ttl_seconds)
        self._executor = Executor(registry, self._engine, self._gate, world)
        self.audit = audit if audit is not None else AuditLog(hmac_key)
        self.evidence = evidence if evidence is not None else EvidenceStore()
        self._states: dict[str, _RequestState] = {}
        self._unparsed = 0
        self._duplicates = 0

    # ------------------------------------------------------------------ public API

    def submit(self, raw: ToolRequest | Mapping[str, Any]) -> HarnessResult:
        try:
            request = raw if isinstance(raw, ToolRequest) else ToolRequest.from_mapping(raw)
        except MalformedRequestError as exc:
            return self.reject_malformed(str(exc))
        if request.request_id in self._states:
            return self._reject_duplicate(request)

        decision = self._engine.evaluate(request)
        state = _RequestState(
            request=request,
            decision=decision,
            evidence_ref=f"ev-{request.request_id}",
            reason_code=decision.reason_code,
            reason=decision.reason,
        )
        self._states[request.request_id] = state
        self._emit(state, "policy.decision")

        if decision.decision is Decision.DENY:
            return self._finish(state, Outcome.DENIED)
        if decision.decision is Decision.REQUIRE_APPROVAL:
            record = self._gate.open(request, _required(decision.risk, "decision risk"))
            state.approval_id = record.approval_id
            state.approval_status = record.status
            state.logged_approval_status = record.status
            state.outcome = Outcome.PENDING_APPROVAL
            state.reason_code = ReasonCode.APPROVAL_PENDING
            state.reason = "Waiting for explicit human approval"
            self._emit(state, "approval.requested")
            return self._result(state)
        return self._execute_and_verify(state, None)

    def approve(self, approval_id: str, approver: str, note: str = "") -> None:
        state = self._state_for_approval(approval_id)
        self._gate.approve(approval_id, approver, note)
        self._sync_approval(state)

    def reject(self, approval_id: str, approver: str, note: str = "") -> None:
        state = self._state_for_approval(approval_id)
        self._gate.reject(approval_id, approver, note)
        self._sync_approval(state)
        self.resume(state.request.request_id)  # rejection is terminal: finish and record it

    def resume(self, request_id: str) -> HarnessResult:
        state = self._states.get(request_id)
        if state is None:
            raise ApprovalError("unknown", "no such request")
        if state.finished:
            return self._result(state)
        approval_id = _required(state.approval_id, "approval id")
        status = self._sync_approval(state)
        if status is ApprovalStatus.PENDING:
            return self._result(state)
        if status is ApprovalStatus.REJECTED:
            return self._finish(state, Outcome.REJECTED)
        if status is ApprovalStatus.EXPIRED:
            return self._finish(state, Outcome.EXPIRED)
        return self._execute_and_verify(state, approval_id)

    # ------------------------------------------------------------------ internals

    def _state_for_approval(self, approval_id: str) -> _RequestState:
        for state in self._states.values():
            if state.approval_id == approval_id:
                return state
        raise ApprovalError("unknown", "no such approval")

    def _sync_approval(self, state: _RequestState) -> ApprovalStatus:
        record = self._gate.get(_required(state.approval_id, "approval id"))
        state.approval_status = record.status
        if record.status is not state.logged_approval_status:
            state.logged_approval_status = record.status
            if record.status is not ApprovalStatus.PENDING:
                code, text = _APPROVAL_RESOLUTIONS[record.status]
                state.outcome = Outcome.IN_PROGRESS
                state.reason_code = code
                state.reason = text.format(by=record.decided_by)
            self._emit(state, f"approval.{record.status.value.lower()}")
        return record.status

    def _execute_and_verify(self, state: _RequestState, approval_id: str | None) -> HarnessResult:
        try:
            record = self._executor.execute(state.request, approval_id)
        except ExecutionRefusedError as exc:
            state.reason_code = (
                ReasonCode(exc.code) if exc.code in ReasonCode else ReasonCode.POLICY_CHANGED
            )
            state.reason = redact_string(str(exc))
            return self._finish(state, Outcome.DENIED)

        state.execution = record
        state.execution_status = record.status
        if record.approval is not None:
            state.approval_status = record.approval.status
        entry = _required(self._registry._entry(state.request.tool), "registry entry")
        self._emit(
            state,
            "execution.finished",
            reason=record.error or "Tool handler returned a result",
        )

        if record.status is ExecutionStatus.FAILED:
            state.reason_code = ReasonCode.EXECUTION_ERROR
            state.reason = record.error or "execution failed"
            if record.before_digest != record.after_digest:
                state.verification = VerificationResult(
                    VerificationStatus.NOT_VERIFIED,
                    (),
                    "execution failed after the environment state had changed",
                )
                state.extras["partial_effects_detected"] = True
                self._emit(state, "verification.finished", reason=state.verification.reason)
            return self._finish(state, Outcome.EXECUTION_FAILED)

        output = _required(record.output, "execution output")
        checks = (
            (state_unchanged(), *entry.checks) if not entry.spec.has_side_effects else entry.checks
        )
        ctx = VerificationContext(
            request=state.request,
            spec=entry.spec,
            output=output,
            world=self._world.reader,
            before_counters=record.before_counters,
            before_digest=record.before_digest,
            after_digest=record.after_digest,
        )
        state.verification = run_checks(checks, ctx)
        status = state.verification.status
        self._emit(state, "verification.finished", reason=state.verification.reason)
        if status is VerificationStatus.VERIFIED:
            state.reason_code = ReasonCode.EXECUTION_COMPLETED
            state.reason = "Execution succeeded and the outcome was verified"
            return self._finish(state, Outcome.COMPLETED)
        if status is VerificationStatus.NOT_VERIFIED:
            outcome, state.reason_code = (
                Outcome.EXECUTED_NOT_VERIFIED,
                ReasonCode.VERIFICATION_NOT_VERIFIED,
            )
        else:
            outcome, state.reason_code = (
                Outcome.EXECUTED_UNCERTAIN,
                ReasonCode.VERIFICATION_UNCERTAIN,
            )
        state.reason = f"Tool reported success but verification is {status.value}"
        return self._finish(state, outcome)

    def _finish(self, state: _RequestState, outcome: Outcome) -> HarnessResult:
        state.outcome = outcome
        state.finished = True
        record = self._evidence_record(state)
        digest = self.evidence.put(state.evidence_ref, record)
        self._emit(state, "request.finished", evidence_digest=digest)
        return self._result(state)

    def _evidence_record(self, state: _RequestState) -> dict[str, Any]:
        req = state.request
        execution = state.execution
        return {
            "evidence_ref": state.evidence_ref,
            "policy_sha256": self._policy.digest,
            "request": {
                "request_id": req.request_id,
                "tool": req.tool,
                "action": req.action,
                "scope": req.scope,
                "requester": req.requester,
                "arguments": redact(dict(req.arguments)),
            },
            "policy_decision": state.decision.to_dict(),
            "approval": self._gate.get(state.approval_id).to_dict() if state.approval_id else None,
            "execution": {
                "status": state.execution_status.value,
                "error": execution.error if execution else None,
                "output": redact(dict(execution.output))
                if execution and execution.output
                else None,
                "state_digest_before": execution.before_digest if execution else None,
                "state_digest_after": execution.after_digest if execution else None,
            },
            "verification": state.verification.to_dict() if state.verification else None,
            "outcome": state.outcome.value,
            "reason_code": state.reason_code.value,
            "reason": state.reason,
            "flags": dict(state.extras),
        }

    def _result(self, state: _RequestState) -> HarnessResult:
        output = state.execution.output if state.execution else None
        return HarnessResult(
            request_id=state.request.request_id,
            decision=state.decision,
            outcome=state.outcome,
            approval_id=state.approval_id,
            approval_status=state.approval_status,
            execution_status=state.execution_status,
            verification=state.verification,
            output=redact(dict(output)) if output is not None else None,
            evidence_ref=state.evidence_ref,
            reason=state.reason,
        )

    def _emit(
        self,
        state: _RequestState,
        event_type: str,
        *,
        reason: str | None = None,
        evidence_digest: str | None = None,
    ) -> None:
        req = state.request
        verification = (
            state.verification.status if state.verification else VerificationStatus.NOT_RUN
        )
        self.audit.append(
            AuditEvent(
                seq=0,
                timestamp=self._clock().isoformat(),
                request_id=req.request_id,
                event_type=event_type,
                tool=req.tool,
                action=req.action,
                risk=state.decision.risk_label,
                scope=req.scope,
                policy_decision=state.decision.decision.value,
                reason_code=state.reason_code.value,
                reason=reason if reason is not None else state.reason,
                approval_status=state.approval_status.value,
                execution_status=state.execution_status.value,
                verification_status=verification.value,
                outcome=state.outcome.value,
                evidence_ref=state.evidence_ref,
                evidence_digest=evidence_digest,
                arguments=dict(req.arguments),
                prev_hash="",
                hash="",
            )
        )

    def _synthetic_request(self, request_id: str, tool: str, action: str) -> ToolRequest:
        return ToolRequest(request_id, tool, action, "unparsed:request", {}, "unknown")

    def reject_malformed(self, message: str) -> HarnessResult:
        """Record a denial for input that could not be parsed into a request at all."""
        self._unparsed += 1
        request = self._synthetic_request(f"unparsed-{self._unparsed:04d}", "unparsed", "unparsed")
        return self._synthetic_denial(request, ReasonCode.MALFORMED_REQUEST, message)

    def _reject_duplicate(self, request: ToolRequest) -> HarnessResult:
        self._duplicates += 1
        return self._synthetic_denial(
            request,
            ReasonCode.DUPLICATE_REQUEST_ID,
            "Request id was already used; replays are denied",
            ref_suffix=f"-dup{self._duplicates}",
        )

    def _synthetic_denial(
        self, request: ToolRequest, code: ReasonCode, message: str, ref_suffix: str = ""
    ) -> HarnessResult:
        decision = PolicyDecision(
            Decision.DENY, request.tool, request.action, request.scope, None, code, message
        )
        state = _RequestState(
            request=request,
            decision=decision,
            evidence_ref=f"ev-{request.request_id}{ref_suffix}",
            reason_code=code,
            reason=message,
        )
        self._emit(state, "policy.decision")
        state.outcome = Outcome.DENIED
        state.finished = True
        digest = self.evidence.put(state.evidence_ref, self._evidence_record(state))
        self._emit(state, "request.finished", evidence_digest=digest)
        return self._result(state)
