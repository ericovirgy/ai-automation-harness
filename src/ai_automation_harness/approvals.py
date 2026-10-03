"""Approval gate. Approval is explicit, bound to exact arguments, expiring and single-use."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

from ai_automation_harness.errors import ApprovalError
from ai_automation_harness.models import IDENTIFIER_RE, ApprovalStatus, Risk, ToolRequest

Clock = Callable[[], datetime]


def system_clock() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    request_id: str
    tool: str
    action: str
    requester: str
    risk: Risk
    arguments_digest: str
    status: ApprovalStatus
    created_at: datetime
    expires_at: datetime
    decided_by: str | None = None
    decided_at: datetime | None = None
    note: str = ""
    consumed: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "approval_id": self.approval_id,
            "request_id": self.request_id,
            "status": self.status.value,
            "requester": self.requester,
            "decided_by": self.decided_by,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "consumed": self.consumed,
        }


class ApprovalGate:
    def __init__(self, clock: Clock, ttl_seconds: int) -> None:
        self._clock = clock
        self._ttl = timedelta(seconds=ttl_seconds)
        self._records: dict[str, ApprovalRecord] = {}

    def open(self, request: ToolRequest, risk: Risk) -> ApprovalRecord:
        approval_id = f"appr-{request.request_id}"
        if approval_id in self._records:
            raise ApprovalError("duplicate", "an approval already exists for this request")
        now = self._clock()
        record = ApprovalRecord(
            approval_id=approval_id,
            request_id=request.request_id,
            tool=request.tool,
            action=request.action,
            requester=request.requester,
            risk=risk,
            arguments_digest=request.arguments_digest,
            status=ApprovalStatus.PENDING,
            created_at=now,
            expires_at=now + self._ttl,
        )
        self._records[approval_id] = record
        return record

    def get(self, approval_id: str) -> ApprovalRecord:
        record = self._records.get(approval_id)
        if record is None:
            raise ApprovalError("unknown", "no such approval")
        if (
            record.status in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED)
            and not record.consumed
            and self._clock() >= record.expires_at
        ):
            record = replace(record, status=ApprovalStatus.EXPIRED)
            self._records[approval_id] = record
        return record

    def approve(self, approval_id: str, approver: str, note: str = "") -> ApprovalRecord:
        return self._decide(approval_id, approver, note, ApprovalStatus.APPROVED)

    def reject(self, approval_id: str, approver: str, note: str = "") -> ApprovalRecord:
        return self._decide(approval_id, approver, note, ApprovalStatus.REJECTED)

    def _decide(
        self, approval_id: str, approver: str, note: str, status: ApprovalStatus
    ) -> ApprovalRecord:
        if not isinstance(approver, str) or not IDENTIFIER_RE.fullmatch(approver):
            raise ApprovalError("invalid_approver", "approver must be a named identity")
        record = self.get(approval_id)
        if record.status is not ApprovalStatus.PENDING:
            raise ApprovalError("not_pending", f"approval is {record.status.value}, not PENDING")
        if approver == record.requester:
            raise ApprovalError("self_approval", "the requester cannot decide its own approval")
        record = replace(
            record, status=status, decided_by=approver, decided_at=self._clock(), note=note[:256]
        )
        self._records[approval_id] = record
        return record

    def consume(self, approval_id: str, request: ToolRequest) -> ApprovalRecord:
        """Atomically validate and spend an approval. Raises ApprovalError unless usable."""
        record = self.get(approval_id)
        if record.status is not ApprovalStatus.APPROVED:
            raise ApprovalError("not_approved", f"approval is {record.status.value}")
        if record.consumed:
            raise ApprovalError("already_consumed", "approval was already used")
        if (
            record.request_id != request.request_id
            or record.tool != request.tool
            or record.action != request.action
            or record.arguments_digest != request.arguments_digest
        ):
            raise ApprovalError("mismatch", "approval does not match this exact request")
        record = replace(record, consumed=True)
        self._records[approval_id] = record
        return record
