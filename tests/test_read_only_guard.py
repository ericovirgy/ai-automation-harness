"""A future developer must not be able to casually add write capability to a read-only client.

Three independent tripwires:
1. the public surface of the read-only world is pinned: adding any method fails the suite;
2. no read-only tool handler may reference the write side or private state;
3. every read-only tool is run for real and must leave the world's digest unchanged.
"""

from __future__ import annotations

import inspect
from typing import Any

from ai_automation_harness import Harness, Outcome, SideEffect
from ai_automation_harness.registry import MUTATING_VERBS
from ai_automation_harness.tools.demo import build_demo_registry
from ai_automation_harness.world import ReadOnlyWorld, SimulatedWorld, WritableWorld

from .conftest import HarnessFactory, req

PINNED_READ_ONLY_SURFACE = frozenset(
    {
        "get_account",
        "read_file",
        "file_exists",
        "search_records",
        "get_draft",
        "outbox_messages",
        "get_receipt",
        "counters",
        "digest",
    }
)
PINNED_WRITE_SURFACE = frozenset({"create_draft", "send_email", "delete_file"})


def public_surface(cls: type) -> frozenset[str]:
    return frozenset(
        name
        for name, member in inspect.getmembers(cls)
        if not name.startswith("_") and callable(member)
    )


def test_read_only_world_surface_is_pinned() -> None:
    """If this fails you added a method to the read-only client. Is it truly read-only?

    If yes, extend PINNED_READ_ONLY_SURFACE deliberately. If it mutates anything, it belongs
    on WritableWorld and must be reachable only by tools that declare side effects.
    """
    assert public_surface(ReadOnlyWorld) == PINNED_READ_ONLY_SURFACE


def test_write_surface_is_pinned_and_lives_only_on_the_writable_world() -> None:
    assert public_surface(WritableWorld) - PINNED_READ_ONLY_SURFACE == PINNED_WRITE_SURFACE
    assert not hasattr(ReadOnlyWorld, "create_draft")


def test_no_read_only_method_name_looks_like_a_mutation() -> None:
    for name in PINNED_READ_ONLY_SURFACE:
        assert not set(name.split("_")) & MUTATING_VERBS, name


def test_the_pin_actually_detects_a_smuggled_write_method() -> None:
    class Tampered(ReadOnlyWorld):
        def write_file(self, path: str, content: str) -> None:
            self._state.files[path] = content

    assert public_surface(Tampered) != PINNED_READ_ONLY_SURFACE
    assert public_surface(Tampered) - PINNED_READ_ONLY_SURFACE == {"write_file"}


def test_read_only_handlers_never_reference_the_write_side() -> None:
    registry = build_demo_registry()
    checked = 0
    for name in registry.names():
        spec = registry.get(name)
        entry = registry._entry(name)
        assert spec is not None and entry is not None
        if spec.side_effects is not SideEffect.NONE:
            continue
        source = inspect.getsource(entry.handler)
        assert "writer" not in source and "_state" not in source, name
        checked += 1
    assert checked >= 3


def test_every_read_only_tool_leaves_the_world_unchanged(make_harness: HarnessFactory) -> None:
    world = SimulatedWorld()
    harness: Harness = make_harness(world=world)
    calls: list[dict[str, Any]] = [
        {"tool": "read_account", "action": "read", "scope": "accounts:read",
         "arguments": {"account_id": "acct-1001"}},
        {"tool": "search_records", "action": "search", "scope": "records:read",
         "arguments": {"query": "invoice"}},
        {"tool": "read_file", "action": "read", "scope": "files:read",
         "arguments": {"path": "docs/readme.txt"}},
    ]  # fmt: skip
    before = world.reader.digest()
    for index, call in enumerate(calls):
        result = harness.submit(req(f"ro{index}", **call))
        assert result.outcome is Outcome.COMPLETED
        assert result.verification is not None
        assert result.verification.checks[0].name == "state_unchanged"
    assert world.reader.digest() == before


def test_tools_without_side_effects_are_never_handed_a_writer() -> None:
    seen: list[object] = []
    registry = build_demo_registry()
    entry = registry._entry("read_account")
    assert entry is not None
    original = entry.handler

    def spy(ctx: Any) -> Any:
        seen.append(ctx.writer)
        return original(ctx)

    object.__setattr__(entry, "handler", spy)
    world = SimulatedWorld()
    from ai_automation_harness import Harness as H
    from ai_automation_harness.models import ToolRequest

    from .conftest import make_policy

    harness = H(registry, make_policy(), world)
    harness.submit(
        ToolRequest("r1", "read_account", "read", "accounts:read", {"account_id": "acct-1001"})
    )
    assert seen == [None]
