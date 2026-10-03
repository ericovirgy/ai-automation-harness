"""ai-automation-harness: policy-controlled, observable and verifiable tool execution."""

from ai_automation_harness.audit import AuditEvent, AuditLog, verify_chain
from ai_automation_harness.harness import Harness, HarnessResult
from ai_automation_harness.models import (
    ApprovalStatus,
    Decision,
    ExecutionStatus,
    Outcome,
    PolicyDecision,
    ReasonCode,
    Risk,
    SideEffect,
    ToolRequest,
    VerificationStatus,
)
from ai_automation_harness.policy import Policy, PolicyEngine
from ai_automation_harness.registry import ArgSpec, ToolRegistry, ToolSpec

__version__ = "0.1.0"

__all__ = [
    "ApprovalStatus",
    "ArgSpec",
    "AuditEvent",
    "AuditLog",
    "Decision",
    "ExecutionStatus",
    "Harness",
    "HarnessResult",
    "Outcome",
    "Policy",
    "PolicyDecision",
    "PolicyEngine",
    "ReasonCode",
    "Risk",
    "SideEffect",
    "ToolRegistry",
    "ToolRequest",
    "ToolSpec",
    "VerificationStatus",
    "__version__",
    "verify_chain",
]
