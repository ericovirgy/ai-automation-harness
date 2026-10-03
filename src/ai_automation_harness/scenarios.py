"""Deterministic scenario runner: requests plus expected decisions, executed through the harness."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ai_automation_harness.audit import AuditLog
from ai_automation_harness.errors import HarnessError
from ai_automation_harness.evidence import EvidenceStore
from ai_automation_harness.harness import Harness, HarnessResult
from ai_automation_harness.models import Decision, Outcome
from ai_automation_harness.policy import Policy
from ai_automation_harness.tools.demo import build_demo_registry
from ai_automation_harness.world import FAULTS, SimulatedWorld

APPROVAL_ACTIONS = ("none", "approve", "reject", "expire")
SCENARIO_KEYS = {"name", "description", "faults", "request", "approval", "approver", "expect"}


class ManualClock:
    """Deterministic clock: starts at a fixed instant and ticks one second per reading."""

    def __init__(self) -> None:
        self._now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        self._now += timedelta(seconds=1)
        return self._now

    def advance(self, seconds: int) -> None:
        self._now += timedelta(seconds=seconds)


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    faults: frozenset[str]
    request: Mapping[str, Any]
    approval: str
    approver: str
    expect_decision: Decision
    expect_outcome: Outcome


@dataclass(frozen=True)
class ScenarioResult:
    scenario: Scenario
    result: HarnessResult

    @property
    def passed(self) -> bool:
        return (
            self.result.decision.decision is self.scenario.expect_decision
            and self.result.outcome is self.scenario.expect_outcome
        )


def parse_scenarios(raw: object) -> list[Scenario]:
    if not isinstance(raw, list):
        raise HarnessError("scenarios file must contain a JSON list")
    scenarios: list[Scenario] = []
    names: set[str] = set()
    request_ids: set[str] = set()
    for item in raw:
        if not isinstance(item, Mapping) or set(item) - SCENARIO_KEYS:
            raise HarnessError("scenario must be an object with known keys only")
        try:
            name = item["name"]
            expect = item["expect"]
            request = item["request"]
            decision = Decision(expect["decision"])
            outcome = Outcome(expect["outcome"])
        except (KeyError, ValueError, TypeError) as exc:
            raise HarnessError("scenario needs name, request and a valid expect block") from exc
        if not isinstance(name, str) or name in names or not isinstance(request, Mapping):
            raise HarnessError("scenario names must be unique strings and request an object")
        names.add(name)
        request_id = request.get("request_id")
        if isinstance(request_id, str):
            if request_id in request_ids:
                raise HarnessError(f"scenario '{name}' reuses request_id")
            request_ids.add(request_id)
        approval = item.get("approval", "none")
        faults = frozenset(item.get("faults", []))
        if approval not in APPROVAL_ACTIONS or faults - FAULTS:
            raise HarnessError(f"scenario '{name}' has an invalid approval action or fault")
        scenarios.append(
            Scenario(
                name=name,
                description=str(item.get("description", "")),
                faults=faults,
                request=request,
                approval=approval,
                approver=str(item.get("approver", "security-reviewer")),
                expect_decision=decision,
                expect_outcome=outcome,
            )
        )
    return scenarios


def load_scenarios(path: str | Path) -> list[Scenario]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HarnessError(f"cannot read scenarios: {exc}") from exc
    return parse_scenarios(raw)


def run_scenarios(
    scenarios: Sequence[Scenario],
    policy: Policy,
    audit: AuditLog | None = None,
    evidence: EvidenceStore | None = None,
) -> tuple[list[ScenarioResult], AuditLog, EvidenceStore]:
    """Run each scenario in a fresh world, sharing one audit chain and one evidence store."""
    clock = ManualClock()
    audit = audit if audit is not None else AuditLog()
    evidence = evidence if evidence is not None else EvidenceStore()
    results: list[ScenarioResult] = []
    for scenario in scenarios:
        harness = Harness(
            build_demo_registry(),
            policy,
            SimulatedWorld(scenario.faults),
            clock=clock,
            audit=audit,
            evidence=evidence,
        )
        result = harness.submit(dict(scenario.request))
        if result.outcome is Outcome.PENDING_APPROVAL and result.approval_id is not None:
            if scenario.approval == "approve":
                harness.approve(result.approval_id, scenario.approver)
            elif scenario.approval == "reject":
                harness.reject(result.approval_id, scenario.approver)
            elif scenario.approval == "expire":
                clock.advance(policy.approval_ttl_seconds + 1)
            if scenario.approval != "none":
                result = harness.resume(result.request_id)
        results.append(ScenarioResult(scenario, result))
    return results, audit, evidence
