"""Core value types shared by every component."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Any

from ai_automation_harness.errors import MalformedRequestError

IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SCOPE_RE = re.compile(r"^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$")
MAX_ARGUMENTS = 32
MAX_ARGUMENT_STRING = 4096


class Risk(IntEnum):
    """Ordered risk levels attached to tools, never to the model.

    READ      single-object, side-effect-free read
    LOW       read-only but broader (queries, enumeration)
    MEDIUM    reversible change to internal state
    HIGH      external side effect or hard-to-reverse disclosure
    CRITICAL  destructive or irreversible
    """

    READ = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: object) -> Risk:
        if isinstance(value, str) and value in _RISK_BY_LABEL:
            return _RISK_BY_LABEL[value]
        raise ValueError(f"unknown risk label (expected one of {sorted(_RISK_BY_LABEL)})")


_RISK_BY_LABEL = {r.label: r for r in Risk}


class SideEffect(IntEnum):
    NONE = 0
    INTERNAL = 1
    EXTERNAL = 2

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: object) -> SideEffect:
        if isinstance(value, str) and value.upper() in cls.__members__:
            return cls[value.upper()]
        raise ValueError("unknown side effect (expected none, internal or external)")


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ApprovalStatus(StrEnum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ExecutionStatus(StrEnum):
    NOT_EXECUTED = "NOT_EXECUTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class VerificationStatus(StrEnum):
    """NOT_RUN means no verification was applicable; it is never a pass."""

    NOT_RUN = "NOT_RUN"
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"
    UNCERTAIN = "UNCERTAIN"


class Outcome(StrEnum):
    """Final disposition of a request. Only COMPLETED means verified success.

    IN_PROGRESS appears only on intermediate audit events, never as a final result.
    """

    IN_PROGRESS = "IN_PROGRESS"
    DENIED = "DENIED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    EXECUTED_NOT_VERIFIED = "EXECUTED_NOT_VERIFIED"
    EXECUTED_UNCERTAIN = "EXECUTED_UNCERTAIN"
    COMPLETED = "COMPLETED"


class ReasonCode(StrEnum):
    """Machine-readable reasons. Stable identifiers, safe to match on."""

    MALFORMED_REQUEST = "malformed_request"
    DUPLICATE_REQUEST_ID = "duplicate_request_id"
    UNKNOWN_TOOL = "unknown_tool"
    UNDECLARED_ACTION = "undeclared_action"
    SIDE_EFFECT_MISMATCH = "side_effect_mismatch"
    SCOPE_NOT_DECLARED = "scope_not_declared_by_tool"
    INVALID_ARGUMENTS = "invalid_arguments"
    TOOL_DENIED = "tool_denied_by_policy"
    TOOL_NOT_ALLOWED = "tool_not_in_allowed_tools"
    ACTION_NOT_PERMITTED = "action_not_permitted_by_policy"
    SCOPE_NOT_GRANTED = "scope_not_granted_by_policy"
    ARGUMENT_NOT_ALLOWLISTED = "argument_not_allowlisted"
    RISK_ABOVE_CEILING = "risk_above_policy_ceiling"
    APPROVAL_TOOL_DECLARATION = "approval_required_by_tool_declaration"
    APPROVAL_EXTERNAL_SIDE_EFFECT = "approval_required_external_side_effect"
    APPROVAL_CRITICAL_RISK = "approval_required_critical_risk"
    APPROVAL_RISK_THRESHOLD = "approval_required_risk_above_auto_threshold"
    APPROVAL_POLICY_RULE = "approval_required_by_policy_rule"
    ALLOWED = "allowed_by_policy"
    APPROVAL_PENDING = "approval_pending"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_INVALID = "approval_invalid"
    POLICY_CHANGED = "policy_decision_changed"
    EXECUTION_ERROR = "execution_error"
    EXECUTION_COMPLETED = "execution_completed"
    VERIFICATION_NOT_VERIFIED = "verification_not_verified"
    VERIFICATION_UNCERTAIN = "verification_uncertain"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _check_identifier(value: object, field_name: str) -> str:
    if type(value) is not str or not IDENTIFIER_RE.fullmatch(value):
        raise MalformedRequestError(f"field '{field_name}' must match {IDENTIFIER_RE.pattern}")
    return value


@dataclass(frozen=True)
class ToolRequest:
    """A request from an agent to use a tool. Validated structurally on construction.

    `side_effect` is the caller's claim about what the call does. The tool declaration is
    authoritative: a claim that differs from it is denied by the policy engine.
    """

    request_id: str
    tool: str
    action: str
    scope: str
    arguments: Mapping[str, str | int | bool] = field(default_factory=dict)
    requester: str = "agent"
    side_effect: SideEffect | None = None

    def __post_init__(self) -> None:
        _check_identifier(self.request_id, "request_id")
        _check_identifier(self.tool, "tool")
        _check_identifier(self.action, "action")
        _check_identifier(self.requester, "requester")
        if type(self.scope) is not str or not SCOPE_RE.fullmatch(self.scope):
            raise MalformedRequestError("field 'scope' must look like 'resource:verb'")
        if self.side_effect is not None and not isinstance(self.side_effect, SideEffect):
            raise MalformedRequestError("field 'side_effect' has the wrong type")
        if not isinstance(self.arguments, Mapping) or len(self.arguments) > MAX_ARGUMENTS:
            raise MalformedRequestError("field 'arguments' must be a small mapping")
        for key, value in self.arguments.items():
            if type(key) is not str or not IDENTIFIER_RE.fullmatch(key):
                raise MalformedRequestError("argument names must be simple identifiers")
            if type(value) not in (str, int, bool):
                raise MalformedRequestError(f"argument '{key}' must be a string, int or bool")
            if type(value) is str and len(value) > MAX_ARGUMENT_STRING:
                raise MalformedRequestError(f"argument '{key}' is too long")
        object.__setattr__(self, "arguments", MappingProxyType(dict(self.arguments)))

    @classmethod
    def from_mapping(cls, raw: object) -> ToolRequest:
        if not isinstance(raw, Mapping):
            raise MalformedRequestError("request must be a mapping")
        allowed = {"request_id", "tool", "action", "scope", "arguments", "requester", "side_effect"}
        unknown = [k for k in raw if k not in allowed]
        if unknown:
            raise MalformedRequestError(f"request has {len(unknown)} unknown field(s)")
        missing = [k for k in ("request_id", "tool", "action", "scope") if k not in raw]
        if missing:
            raise MalformedRequestError(f"missing request fields: {missing}")
        side_effect: SideEffect | None = None
        if raw.get("side_effect") is not None:
            try:
                side_effect = SideEffect.parse(raw["side_effect"])
            except ValueError as exc:
                raise MalformedRequestError(str(exc)) from exc
        return cls(
            request_id=raw["request_id"],
            tool=raw["tool"],
            action=raw["action"],
            scope=raw["scope"],
            arguments=raw.get("arguments", {}),
            requester=raw.get("requester", "agent"),
            side_effect=side_effect,
        )

    @property
    def arguments_digest(self) -> str:
        """Digest of the raw arguments. Binds approvals to exact arguments; never exported."""
        return sha256_hex(canonical_json(dict(self.arguments)))


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    tool: str
    action: str
    scope: str
    risk: Risk | None
    reason_code: ReasonCode
    reason: str
    details: Mapping[str, Any] = field(default_factory=dict)

    @property
    def risk_label(self) -> str:
        return self.risk.label if self.risk is not None else "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "tool": self.tool,
            "action": self.action,
            "scope": self.scope,
            "risk": self.risk_label,
            "reason_code": self.reason_code.value,
            "reason": self.reason,
            "details": dict(self.details),
        }
