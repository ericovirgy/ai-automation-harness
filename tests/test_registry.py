from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from typing import Any

import pytest

from ai_automation_harness import ArgSpec, Risk, SideEffect, ToolRegistry, ToolSpec
from ai_automation_harness.errors import RegistrySealedError, ToolDeclarationError
from ai_automation_harness.registry import ToolContext
from ai_automation_harness.tools.demo import build_demo_registry


def spec(**overrides: Any) -> ToolSpec:
    base: dict[str, Any] = {
        "name": "sample_tool",
        "description": "A sample tool.",
        "risk": Risk.READ,
        "scopes": {"things:read"},
        "side_effects": SideEffect.NONE,
        "allowed_actions": {"read"},
        "requires_approval": False,
    }
    base.update(overrides)
    return ToolSpec(**base)


def noop(ctx: ToolContext) -> dict[str, Any]:
    return {}


def test_valid_declaration_is_accepted_and_normalised() -> None:
    s = spec()
    assert isinstance(s.scopes, frozenset)
    assert isinstance(s.allowed_actions, frozenset)
    assert not s.has_side_effects


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": "Bad-Name"},
        {"name": ""},
        {"description": "   "},
        {"scopes": set()},
        {"scopes": {"no-colon"}},
        {"allowed_actions": set()},
        {"allowed_actions": {"Bad Action"}},
        {"risk": 2},
        {"arguments": {"Bad": ArgSpec()}},
        # consistency rules between risk, side effects and approval
        {"risk": Risk.HIGH},  # high without approval
        {"risk": Risk.MEDIUM, "side_effects": SideEffect.NONE},
        {"risk": Risk.READ, "side_effects": SideEffect.INTERNAL},
        {"risk": Risk.MEDIUM, "side_effects": SideEffect.EXTERNAL, "requires_approval": False},
    ],
)
def test_invalid_declarations_are_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ToolDeclarationError):
        spec(**overrides)


@pytest.mark.parametrize("verb", ["write", "delete", "create", "send", "update", "exec", "run"])
def test_read_only_tool_cannot_declare_a_mutating_action(verb: str) -> None:
    """Tripwire: a tool without side effects cannot expose a write-sounding action."""
    with pytest.raises(ToolDeclarationError):
        spec(allowed_actions={"read", verb})


def test_arg_spec_rejects_bad_pattern() -> None:
    with pytest.raises(ToolDeclarationError):
        ArgSpec(pattern="(")


def test_specs_are_immutable_after_declaration() -> None:
    s = spec()
    with pytest.raises(FrozenInstanceError):
        s.risk = Risk.CRITICAL  # type: ignore[misc]
    with pytest.raises(AttributeError):
        s.allowed_actions.add("write")  # type: ignore[attr-defined]
    with pytest.raises(TypeError):
        s.arguments["x"] = ArgSpec()  # type: ignore[index]


def test_unknown_tool_is_not_in_registry() -> None:
    registry = build_demo_registry()
    assert registry.get("transfer_funds") is None
    assert registry._entry("transfer_funds") is None


def test_duplicate_registration_is_rejected() -> None:
    registry = ToolRegistry()
    registry.register(spec(), noop)
    with pytest.raises(ToolDeclarationError):
        registry.register(spec(), noop)


def test_registering_a_non_spec_is_rejected() -> None:
    with pytest.raises(ToolDeclarationError):
        ToolRegistry().register({"name": "x"}, noop)  # type: ignore[arg-type]


def test_sealed_registry_refuses_new_tools() -> None:
    registry = build_demo_registry()
    registry.seal()
    assert registry.sealed
    with pytest.raises(RegistrySealedError):
        registry.register(spec(), noop)


def test_registry_does_not_expose_handlers_publicly() -> None:
    registry = build_demo_registry()
    public = [n for n in dir(registry) if not n.startswith("_")]
    assert set(public) == {
        "register",
        "seal",
        "sealed",
        "get",
        "names",
        "explicit_check_count",
    }
    assert not callable(registry.get("read_account"))


def test_argument_validation_reports_each_problem() -> None:
    s = spec(
        arguments={
            "n": ArgSpec(type="int", min_value=1, max_value=5),
            "flag": ArgSpec(type="bool", required=False),
            "name": ArgSpec(pattern=r"[a-z]+", max_length=4),
        }
    )
    assert s.argument_problems({"n": 3, "name": "abc"}) == []
    assert s.argument_problems({"n": True, "name": "abc"})  # bool is not an int
    assert s.argument_problems({"n": 0, "name": "abc"})
    assert s.argument_problems({"n": 9, "name": "abc"})
    assert s.argument_problems({"n": 3, "name": "ABC"})
    assert s.argument_problems({"n": 3, "name": "abcde"})
    assert s.argument_problems({"n": 3, "name": 5})
    assert s.argument_problems({"n": 3, "name": "abc", "flag": "yes"})
    assert s.argument_problems({"name": "abc"})  # missing required
    assert s.argument_problems({"n": 3, "name": "abc", "extra": 1})  # unexpected


def test_replace_cannot_smuggle_an_invalid_spec() -> None:
    with pytest.raises(ToolDeclarationError):
        replace(spec(), risk=Risk.CRITICAL)  # still read-only side effects, critical risk
