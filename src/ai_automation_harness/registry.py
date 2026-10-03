"""Tool registry. Every tool must be declared here before it can run; unknown tools fail closed."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal

from ai_automation_harness.errors import RegistrySealedError, ToolDeclarationError
from ai_automation_harness.models import SCOPE_RE, Risk, SideEffect, ToolRequest
from ai_automation_harness.verification import Check
from ai_automation_harness.world import ReadOnlyWorld, WritableWorld

TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")

# Heuristic tripwire, not a guarantee: a tool declared without side effects must not expose
# an action whose name suggests a mutation. The real controls are the read-only world handed
# to such tools and the state_unchanged invariant checked after every run.
MUTATING_VERBS = frozenset(
    {
        "write", "delete", "remove", "create", "send", "update", "set", "put", "post",
        "patch", "drop", "exec", "execute", "run", "move", "rename", "upload", "insert",
    }
)  # fmt: skip


@dataclass(frozen=True)
class ArgSpec:
    type: Literal["str", "int", "bool"] = "str"
    required: bool = True
    max_length: int = 256
    pattern: str | None = None
    min_value: int | None = None
    max_value: int | None = None

    def __post_init__(self) -> None:
        if self.type not in ("str", "int", "bool"):
            raise ToolDeclarationError("ArgSpec.type must be 'str', 'int' or 'bool'")
        if self.pattern is not None:
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ToolDeclarationError("ArgSpec.pattern is not a valid regex") from exc

    def problems(self, name: str, value: object) -> list[str]:
        if self.type == "bool":
            return [] if isinstance(value, bool) else [f"argument '{name}' must be a bool"]
        if self.type == "int":
            if isinstance(value, bool) or not isinstance(value, int):
                return [f"argument '{name}' must be an int"]
            if self.min_value is not None and value < self.min_value:
                return [f"argument '{name}' is below the minimum"]
            if self.max_value is not None and value > self.max_value:
                return [f"argument '{name}' is above the maximum"]
            return []
        if not isinstance(value, str):
            return [f"argument '{name}' must be a string"]
        if len(value) > self.max_length:
            return [f"argument '{name}' exceeds max length {self.max_length}"]
        if self.pattern is not None and not re.fullmatch(self.pattern, value):
            return [f"argument '{name}' does not match the required pattern"]
        return []


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    risk: Risk
    scopes: frozenset[str]
    side_effects: SideEffect
    allowed_actions: frozenset[str]
    requires_approval: bool
    arguments: Mapping[str, ArgSpec] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "scopes", frozenset(self.scopes))
        object.__setattr__(self, "allowed_actions", frozenset(self.allowed_actions))
        object.__setattr__(self, "arguments", MappingProxyType(dict(self.arguments)))
        self._validate()

    def _validate(self) -> None:
        if not TOOL_NAME_RE.fullmatch(self.name):
            raise ToolDeclarationError(f"tool name must match {TOOL_NAME_RE.pattern}")
        if not self.description.strip():
            raise ToolDeclarationError(f"tool '{self.name}' needs a description")
        if not isinstance(self.risk, Risk) or not isinstance(self.side_effects, SideEffect):
            raise ToolDeclarationError(f"tool '{self.name}' has an invalid risk or side effect")
        if not self.scopes or not all(SCOPE_RE.fullmatch(s) for s in self.scopes):
            raise ToolDeclarationError(f"tool '{self.name}' needs valid scopes")
        if not self.allowed_actions or not all(
            re.fullmatch(r"[a-z][a-z0-9_]{0,31}", a) for a in self.allowed_actions
        ):
            raise ToolDeclarationError(f"tool '{self.name}' needs valid allowed actions")
        if self.side_effects == SideEffect.NONE:
            if self.risk > Risk.LOW:
                raise ToolDeclarationError(
                    f"tool '{self.name}': no side effects implies risk <= low"
                )
            mutating = sorted(self.allowed_actions & MUTATING_VERBS)
            if mutating:
                raise ToolDeclarationError(
                    f"tool '{self.name}' declares no side effects but exposes actions {mutating}"
                )
        else:
            if self.risk == Risk.READ:
                raise ToolDeclarationError(f"tool '{self.name}': side effects imply risk > read")
            if self.side_effects == SideEffect.EXTERNAL and self.risk < Risk.HIGH:
                raise ToolDeclarationError(
                    f"tool '{self.name}': external effects imply risk >= high"
                )
        if self.risk >= Risk.HIGH and not self.requires_approval:
            raise ToolDeclarationError(f"tool '{self.name}': risk >= high requires approval")
        for arg_name, arg in self.arguments.items():
            if not isinstance(arg, ArgSpec) or not re.fullmatch(r"[a-z][a-z0-9_]*", arg_name):
                raise ToolDeclarationError(f"tool '{self.name}' has an invalid argument spec")

    @property
    def has_side_effects(self) -> bool:
        return self.side_effects != SideEffect.NONE

    def argument_problems(self, arguments: Mapping[str, object]) -> list[str]:
        problems = [
            f"unexpected argument '{k}'" for k in sorted(arguments) if k not in self.arguments
        ]
        for name, arg in self.arguments.items():
            if name not in arguments:
                if arg.required:
                    problems.append(f"missing required argument '{name}'")
                continue
            problems.extend(arg.problems(name, arguments[name]))
        return problems


@dataclass(frozen=True)
class ToolContext:
    """What a handler receives. `writer` is None for tools declared without side effects."""

    request: ToolRequest
    reader: ReadOnlyWorld
    writer: WritableWorld | None


Handler = Callable[[ToolContext], Mapping[str, Any]]


@dataclass(frozen=True)
class RegisteredTool:
    spec: ToolSpec
    handler: Handler
    checks: tuple[Check, ...]


class ToolRegistry:
    """Holds declarations and handlers. Handlers are reachable only through the executor."""

    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}
        self._sealed = False

    def register(self, spec: ToolSpec, handler: Handler, checks: Iterable[Check] = ()) -> None:
        if self._sealed:
            raise RegistrySealedError("registry is sealed; tools cannot be added")
        if not isinstance(spec, ToolSpec):
            raise ToolDeclarationError("register() requires a ToolSpec")
        if spec.name in self._tools:
            raise ToolDeclarationError(f"tool '{spec.name}' is already registered")
        self._tools[spec.name] = RegisteredTool(spec, handler, tuple(checks))

    def seal(self) -> None:
        self._sealed = True

    @property
    def sealed(self) -> bool:
        return self._sealed

    def get(self, name: str) -> ToolSpec | None:
        entry = self._tools.get(name)
        return entry.spec if entry else None

    def names(self) -> Sequence[str]:
        return sorted(self._tools)

    def explicit_check_count(self, name: str) -> int:
        entry = self._tools.get(name)
        return len(entry.checks) if entry else 0

    def _entry(self, name: str) -> RegisteredTool | None:
        """Package-private. Used by the executor and the harness only."""
        return self._tools.get(name)
