"""Verification: did the claimed outcome actually happen?

A tool returning success is a claim. Checks compare that claim with observable state.
Aggregation rule: any NOT_VERIFIED wins, else any UNCERTAIN, else VERIFIED. No checks at all
is UNCERTAIN, never VERIFIED.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ai_automation_harness.models import ToolRequest, VerificationStatus
from ai_automation_harness.redaction import redact_string
from ai_automation_harness.world import ReadOnlyWorld

if TYPE_CHECKING:
    from ai_automation_harness.registry import ToolSpec


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: VerificationStatus
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status.value, "detail": self.detail}


@dataclass(frozen=True)
class VerificationContext:
    request: ToolRequest
    spec: ToolSpec
    output: Mapping[str, Any]
    world: ReadOnlyWorld
    before_counters: Mapping[str, int]
    before_digest: str
    after_digest: str


Check = Callable[[VerificationContext], CheckResult]


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    checks: tuple[CheckResult, ...]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reason": self.reason,
            "checks": [c.to_dict() for c in self.checks],
        }


def _result(name: str, status: VerificationStatus, detail: str) -> CheckResult:
    return CheckResult(name=name, status=status, detail=detail)


def output_schema(fields: Mapping[str, type | tuple[type, ...]]) -> Check:
    """Output must be a mapping with every field present and of the declared type."""

    def check(ctx: VerificationContext) -> CheckResult:
        name = "output_schema"
        problems: list[str] = []
        for key, expected in fields.items():
            if key not in ctx.output:
                problems.append(f"missing field '{key}'")
            elif (isinstance(ctx.output[key], bool) and expected is int) or not isinstance(
                ctx.output[key], expected
            ):
                problems.append(f"field '{key}' has the wrong type")
        if problems:
            return _result(name, VerificationStatus.NOT_VERIFIED, "; ".join(problems))
        return _result(name, VerificationStatus.VERIFIED, "output matches the declared schema")

    check.__name__ = "output_schema"
    return check


def expected_state(
    name: str,
    observe: Callable[[VerificationContext], object],
    expected: Callable[[VerificationContext], object],
) -> Check:
    """Read the state back from the environment and compare it with what was claimed.

    An absent state (None) or a mismatch is NOT_VERIFIED. If the state cannot be read at all
    the answer is UNCERTAIN, because absence of evidence is not evidence of failure.
    """

    def check(ctx: VerificationContext) -> CheckResult:
        observed = observe(ctx)
        if observed is None:
            return _result(name, VerificationStatus.NOT_VERIFIED, "expected state is absent")
        if observed != expected(ctx):
            return _result(name, VerificationStatus.NOT_VERIFIED, "observed state differs")
        return _result(name, VerificationStatus.VERIFIED, "observed state matches the claim")

    check.__name__ = name
    return check


def invariant(name: str, predicate: Callable[[VerificationContext], bool]) -> Check:
    """A condition that must hold after execution (for example a bounded blast radius)."""

    def check(ctx: VerificationContext) -> CheckResult:
        if predicate(ctx):
            return _result(name, VerificationStatus.VERIFIED, "invariant holds")
        return _result(name, VerificationStatus.NOT_VERIFIED, "invariant violated")

    check.__name__ = name
    return check


def evidence_exists(
    ref_field: str, lookup: Callable[[VerificationContext, str], object | None]
) -> Check:
    """The output must reference evidence and that evidence must be resolvable.

    No reference at all is UNCERTAIN (nothing to examine). A reference that resolves to
    nothing is NOT_VERIFIED (the claim points at evidence that does not exist).
    """

    def check(ctx: VerificationContext) -> CheckResult:
        name = "evidence_exists"
        ref = ctx.output.get(ref_field)
        if not isinstance(ref, str) or not ref:
            return _result(name, VerificationStatus.UNCERTAIN, f"output has no '{ref_field}'")
        if lookup(ctx, ref) is None:
            return _result(name, VerificationStatus.NOT_VERIFIED, "referenced evidence not found")
        return _result(name, VerificationStatus.VERIFIED, "referenced evidence exists")

    check.__name__ = "evidence_exists"
    return check


def state_unchanged() -> Check:
    """Read-only invariant. Added automatically by the harness for tools without side effects."""

    def check(ctx: VerificationContext) -> CheckResult:
        name = "state_unchanged"
        if ctx.before_digest == ctx.after_digest:
            return _result(name, VerificationStatus.VERIFIED, "environment state is unchanged")
        return _result(
            name, VerificationStatus.NOT_VERIFIED, "tool declared read-only but changed state"
        )

    check.__name__ = "state_unchanged"
    return check


def run_checks(checks: Sequence[Check], ctx: VerificationContext) -> VerificationResult:
    if not checks:
        return VerificationResult(
            VerificationStatus.UNCERTAIN, (), "no verification checks are defined for this tool"
        )
    results: list[CheckResult] = []
    for index, check in enumerate(checks):
        try:
            results.append(check(ctx))
        except Exception as exc:
            results.append(
                _result(
                    getattr(check, "__name__", f"check_{index}"),
                    VerificationStatus.UNCERTAIN,
                    f"check could not be completed: {type(exc).__name__}: "
                    f"{redact_string(str(exc))}",
                )
            )
    statuses = {r.status for r in results}
    if VerificationStatus.NOT_VERIFIED in statuses:
        status, reason = (
            VerificationStatus.NOT_VERIFIED,
            "at least one check contradicted the claim",
        )
    elif VerificationStatus.UNCERTAIN in statuses:
        status, reason = VerificationStatus.UNCERTAIN, "at least one check was inconclusive"
    else:
        status, reason = VerificationStatus.VERIFIED, "all checks passed"
    return VerificationResult(status, tuple(results), reason)
