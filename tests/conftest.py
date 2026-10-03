from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from ai_automation_harness import Harness, Policy, ToolRegistry, ToolRequest
from ai_automation_harness.tools.demo import build_demo_registry
from ai_automation_harness.world import SimulatedWorld

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

BASE_POLICY: dict[str, Any] = {
    "version": 1,
    "allowed_scopes": ["accounts:read", "records:read", "files:read", "drafts:write"],
    "allowed_tools": {
        "read_account": {"scopes": ["accounts:read"]},
        "search_records": {"scopes": ["records:read"]},
        "read_file": {
            "scopes": ["files:read"],
            "argument_allowlists": {"path": ["docs/*"]},
        },
        "create_draft": {
            "scopes": ["drafts:write"],
            "argument_allowlists": {"to": ["*@example.org"]},
        },
    },
    "denied_tools": ["delete_file"],
    "risk": {"max_auto_risk": "low", "max_risk": "high"},
    "approvals": {"ttl_seconds": 900},
    "verification": {"required_from_risk": "read"},
}


class FakeClock:
    """Frozen clock that only moves when the test says so."""

    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


def policy_dict(**overrides: Any) -> dict[str, Any]:
    """BASE_POLICY with top-level overrides. A value of None removes the key."""
    data = deepcopy(BASE_POLICY)
    for key, value in overrides.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    return data


def make_policy(**overrides: Any) -> Policy:
    return Policy.from_mapping(policy_dict(**overrides))


def email_policy() -> Policy:
    data = policy_dict()
    data["allowed_scopes"].append("email:send")
    data["allowed_tools"]["send_email"] = {
        "scopes": ["email:send"],
        "argument_allowlists": {"to": ["*@example.org"]},
    }
    return Policy.from_mapping(data)


def req(
    request_id: str = "r1",
    tool: str = "read_account",
    action: str = "read",
    scope: str = "accounts:read",
    arguments: Mapping[str, Any] | None = None,
    **extra: Any,
) -> ToolRequest:
    if arguments is None:
        arguments = {"account_id": "acct-1001"} if tool == "read_account" else {}
    return ToolRequest(request_id, tool, action, scope, arguments, **extra)


def draft_req(request_id: str = "d1", to: str = "alice@example.org", **extra: Any) -> ToolRequest:
    return ToolRequest(
        request_id,
        "create_draft",
        "create",
        "drafts:write",
        {"to": to, "subject": "Subject", "body": "Body"},
        **extra,
    )


def mail_req(request_id: str = "m1", to: str = "alice@example.org") -> ToolRequest:
    return ToolRequest(
        request_id,
        "send_email",
        "send",
        "email:send",
        {"to": to, "subject": "Subject", "body": "Body"},
    )


HarnessFactory = Callable[..., Harness]


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def world() -> SimulatedWorld:
    return SimulatedWorld()


@pytest.fixture
def make_harness(clock: FakeClock) -> HarnessFactory:
    def factory(
        policy: Policy | None = None,
        registry: ToolRegistry | None = None,
        world: SimulatedWorld | None = None,
        **kwargs: Any,
    ) -> Harness:
        return Harness(
            registry if registry is not None else build_demo_registry(),
            policy if policy is not None else make_policy(),
            world if world is not None else SimulatedWorld(),
            clock=clock,
            **kwargs,
        )

    return factory


@pytest.fixture
def harness(make_harness: HarnessFactory) -> Harness:
    return make_harness()
