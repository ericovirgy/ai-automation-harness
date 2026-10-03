"""Policy loading (strict, fail closed) and deterministic evaluation."""

from __future__ import annotations

import fnmatch
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

import yaml

from ai_automation_harness.errors import MalformedPolicyError
from ai_automation_harness.models import (
    SCOPE_RE,
    Decision,
    PolicyDecision,
    ReasonCode,
    Risk,
    SideEffect,
    ToolRequest,
    canonical_json,
    sha256_hex,
)
from ai_automation_harness.registry import TOOL_NAME_RE, ToolRegistry, ToolSpec

MAX_POLICY_BYTES = 256 * 1024
MAX_AUTO_RISK_CAP = Risk.MEDIUM
TOP_LEVEL_KEYS = {
    "version",
    "allowed_tools",
    "denied_tools",
    "allowed_scopes",
    "risk",
    "approvals",
    "verification",
}


@dataclass(frozen=True)
class ToolRule:
    scopes: frozenset[str]
    actions: frozenset[str] | None
    approval: Literal["auto", "required"]
    argument_allowlists: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True)
class Policy:
    allowed_tools: Mapping[str, ToolRule]
    denied_tools: frozenset[str]
    allowed_scopes: frozenset[str]
    max_auto_risk: Risk
    max_risk: Risk
    approval_ttl_seconds: int
    verification_required_from: Risk
    digest: str

    @classmethod
    def from_mapping(cls, raw: object) -> Policy:
        return _parse(raw)

    @classmethod
    def from_text(cls, text: str, fmt: Literal["yaml", "json"] = "yaml") -> Policy:
        if len(text.encode("utf-8")) > MAX_POLICY_BYTES:
            raise MalformedPolicyError("policy document is too large")
        try:
            raw = _load_json(text) if fmt == "json" else _load_yaml(text)
        except (yaml.YAMLError, json.JSONDecodeError, ValueError) as exc:
            raise MalformedPolicyError(f"policy is not valid {fmt}: {exc}") from exc
        return _parse(raw)

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        p = Path(path)
        if p.suffix.lower() not in (".yaml", ".yml", ".json"):
            raise MalformedPolicyError("policy file must end in .yaml, .yml or .json")
        try:
            if p.stat().st_size > MAX_POLICY_BYTES:
                raise MalformedPolicyError("policy document is too large")
            text = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise MalformedPolicyError(f"cannot read policy file: {exc.strerror}") from exc
        return cls.from_text(text, "json" if p.suffix.lower() == ".json" else "yaml")

    def validate_against(self, registry: ToolRegistry) -> None:
        """Reject policies that reference or grant things the registry does not declare."""
        for name, rule in self.allowed_tools.items():
            spec = registry.get(name)
            if spec is None:
                raise MalformedPolicyError(f"allowed_tools references undeclared tool '{name}'")
            if not rule.scopes <= spec.scopes:
                raise MalformedPolicyError(f"tool '{name}': policy grants scopes the tool lacks")
            if rule.actions is not None and not rule.actions <= spec.allowed_actions:
                raise MalformedPolicyError(f"tool '{name}': policy names undeclared actions")
            unknown_args = set(rule.argument_allowlists) - set(spec.arguments)
            if unknown_args:
                raise MalformedPolicyError(
                    f"tool '{name}': allowlist for undeclared arguments {sorted(unknown_args)}"
                )
        for name in registry.names():
            spec = registry.get(name)
            if (
                spec is not None
                and spec.risk >= self.verification_required_from
                and registry.explicit_check_count(name) == 0
            ):
                raise MalformedPolicyError(
                    f"tool '{name}' has no verification checks but policy requires them"
                )


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate keys and aliases (both create ambiguity)."""

    def compose_node(self, parent: yaml.Node | None, index: int) -> yaml.Node | None:
        if self.check_event(yaml.AliasEvent):
            raise ValueError("YAML anchors and aliases are not allowed in policies")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[object] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if key in seen:
                raise ValueError(f"duplicate key in policy: {key!r}")
            seen.add(key)
        return super().construct_mapping(node, deep)


def _load_yaml(text: str) -> object:
    return yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key in policy: {key!r}")
        result[key] = value
    return result


def _load_json(text: str) -> object:
    return json.loads(text, object_pairs_hook=_no_duplicates)


def _mapping(value: object, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(k, str) for k in value):
        raise MalformedPolicyError(f"{where} must be a mapping with string keys")
    return value


def _only_keys(value: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise MalformedPolicyError(f"{where} has unknown keys: {unknown}")


def _str_list(value: object, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise MalformedPolicyError(f"{where} must be a list of strings")
    if len(set(value)) != len(value):
        raise MalformedPolicyError(f"{where} contains duplicates")
    return value


def _risk(value: object, where: str) -> Risk:
    try:
        return Risk.parse(value)
    except ValueError as exc:
        raise MalformedPolicyError(f"{where}: {exc}") from exc


def _parse_rule(name: str, raw: object) -> ToolRule:
    where = f"allowed_tools.{name}"
    body = _mapping(raw if raw is not None else {}, where)
    _only_keys(body, {"scopes", "actions", "approval", "argument_allowlists"}, where)
    if "scopes" not in body:
        raise MalformedPolicyError(f"{where}.scopes is required (least privilege)")
    scopes = _str_list(body["scopes"], f"{where}.scopes")
    if not scopes or not all(SCOPE_RE.fullmatch(s) for s in scopes):
        raise MalformedPolicyError(f"{where}.scopes must be a non-empty list of 'resource:verb'")
    actions = None
    if "actions" in body:
        actions = frozenset(_str_list(body["actions"], f"{where}.actions"))
        if not actions:
            raise MalformedPolicyError(f"{where}.actions must not be empty")
    approval = body.get("approval", "auto")
    if approval not in ("auto", "required"):
        raise MalformedPolicyError(f"{where}.approval must be 'auto' or 'required'")
    allowlists: dict[str, tuple[str, ...]] = {}
    for arg, patterns in _mapping(
        body.get("argument_allowlists", {}), f"{where}.argument_allowlists"
    ).items():
        values = _str_list(patterns, f"{where}.argument_allowlists.{arg}")
        if not values:
            raise MalformedPolicyError(f"{where}.argument_allowlists.{arg} must not be empty")
        allowlists[arg] = tuple(values)
    return ToolRule(
        scopes=frozenset(scopes),
        actions=actions,
        approval=approval,
        argument_allowlists=MappingProxyType(allowlists),
    )


def _parse(raw: object) -> Policy:
    doc = _mapping(raw, "policy")
    _only_keys(doc, TOP_LEVEL_KEYS, "policy")
    if doc.get("version") != 1 or isinstance(doc.get("version"), bool):
        raise MalformedPolicyError("policy.version must be 1")

    tools_raw = _mapping(doc.get("allowed_tools", {}), "allowed_tools")
    rules: dict[str, ToolRule] = {}
    for name, body in tools_raw.items():
        if not TOOL_NAME_RE.fullmatch(name):
            raise MalformedPolicyError("allowed_tools contains an invalid tool name")
        rules[name] = _parse_rule(name, body)

    denied = _str_list(doc.get("denied_tools", []), "denied_tools")
    if not all(TOOL_NAME_RE.fullmatch(n) for n in denied):
        raise MalformedPolicyError("denied_tools contains an invalid tool name")
    both = sorted(set(denied) & set(rules))
    if both:
        raise MalformedPolicyError(f"ambiguous policy: tools both allowed and denied: {both}")

    scopes = _str_list(doc.get("allowed_scopes", []), "allowed_scopes")
    if not all(SCOPE_RE.fullmatch(s) for s in scopes):
        raise MalformedPolicyError("allowed_scopes entries must look like 'resource:verb'")
    for name, rule in rules.items():
        if not rule.scopes <= set(scopes):
            raise MalformedPolicyError(f"allowed_tools.{name} grants scopes outside allowed_scopes")

    risk = _mapping(doc.get("risk", {}), "risk")
    _only_keys(risk, {"max_auto_risk", "max_risk"}, "risk")
    max_auto = _risk(risk.get("max_auto_risk", "read"), "risk.max_auto_risk")
    max_risk = _risk(risk.get("max_risk", "high"), "risk.max_risk")
    if max_auto > MAX_AUTO_RISK_CAP:
        raise MalformedPolicyError(
            f"risk.max_auto_risk may not exceed {MAX_AUTO_RISK_CAP.label}: "
            "higher-risk actions always need approval"
        )
    if max_auto > max_risk:
        raise MalformedPolicyError("risk.max_auto_risk may not exceed risk.max_risk")

    approvals = _mapping(doc.get("approvals", {}), "approvals")
    _only_keys(approvals, {"ttl_seconds"}, "approvals")
    ttl = approvals.get("ttl_seconds", 900)
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= 86_400:
        raise MalformedPolicyError("approvals.ttl_seconds must be an int between 1 and 86400")

    verification = _mapping(doc.get("verification", {}), "verification")
    _only_keys(verification, {"required_from_risk"}, "verification")
    required_from = _risk(
        verification.get("required_from_risk", "read"), "verification.required_from_risk"
    )

    normalized = {
        "allowed_tools": {
            n: {
                "scopes": sorted(r.scopes),
                "actions": sorted(r.actions) if r.actions else None,
                "approval": r.approval,
                "argument_allowlists": {k: list(v) for k, v in r.argument_allowlists.items()},
            }
            for n, r in sorted(rules.items())
        },
        "denied_tools": sorted(denied),
        "allowed_scopes": sorted(scopes),
        "max_auto_risk": max_auto.label,
        "max_risk": max_risk.label,
        "ttl": ttl,
        "verification_required_from": required_from.label,
    }
    return Policy(
        allowed_tools=MappingProxyType(rules),
        denied_tools=frozenset(denied),
        allowed_scopes=frozenset(scopes),
        max_auto_risk=max_auto,
        max_risk=max_risk,
        approval_ttl_seconds=ttl,
        verification_required_from=required_from,
        digest=sha256_hex(canonical_json(normalized)),
    )


def _unsafe_path_like(value: str) -> bool:
    return "\x00" in value or "\\" in value or ".." in value.split("/")


class PolicyEngine:
    """Deterministic: the same request, registry and policy always yield the same decision."""

    def __init__(self, policy: Policy, registry: ToolRegistry) -> None:
        policy.validate_against(registry)
        self._policy = policy
        self._registry = registry

    @property
    def policy(self) -> Policy:
        return self._policy

    def evaluate(self, request: ToolRequest) -> PolicyDecision:
        spec = self._registry.get(request.tool)
        if spec is None:
            return self._deny(
                request, None, ReasonCode.UNKNOWN_TOOL, "Tool is not declared in the registry"
            )
        structural = self._structural_denial(request, spec)
        if structural is not None:
            return structural
        return self._policy_decision(request, spec)

    def _deny(
        self,
        request: ToolRequest,
        spec: ToolSpec | None,
        code: ReasonCode,
        reason: str,
        details: Mapping[str, Any] | None = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            Decision.DENY,
            request.tool,
            request.action,
            request.scope,
            spec.risk if spec else None,
            code,
            reason,
            details or {},
        )

    def _structural_denial(self, request: ToolRequest, spec: ToolSpec) -> PolicyDecision | None:
        if request.action not in spec.allowed_actions:
            return self._deny(
                request, spec, ReasonCode.UNDECLARED_ACTION, "Action is not declared for this tool"
            )
        if request.side_effect is not None and request.side_effect != spec.side_effects:
            return self._deny(
                request,
                spec,
                ReasonCode.SIDE_EFFECT_MISMATCH,
                "Claimed side effect differs from the tool declaration",
                {"claimed": request.side_effect.label, "declared": spec.side_effects.label},
            )
        if request.scope not in spec.scopes:
            return self._deny(
                request, spec, ReasonCode.SCOPE_NOT_DECLARED, "Scope is not declared by the tool"
            )
        problems = spec.argument_problems(request.arguments)
        if problems:
            return self._deny(
                request,
                spec,
                ReasonCode.INVALID_ARGUMENTS,
                "Arguments failed validation",
                {"problems": problems},
            )
        return None

    def _policy_decision(self, request: ToolRequest, spec: ToolSpec) -> PolicyDecision:
        policy = self._policy
        if spec.name in policy.denied_tools:
            return self._deny(
                request, spec, ReasonCode.TOOL_DENIED, "Tool is explicitly denied by policy"
            )
        rule = policy.allowed_tools.get(spec.name)
        if rule is None:
            return self._deny(
                request,
                spec,
                ReasonCode.TOOL_NOT_ALLOWED,
                "Tool is not in allowed_tools (deny by default)",
            )
        if rule.actions is not None and request.action not in rule.actions:
            return self._deny(
                request, spec, ReasonCode.ACTION_NOT_PERMITTED, "Action is not permitted by policy"
            )
        if request.scope not in rule.scopes or request.scope not in policy.allowed_scopes:
            return self._deny(
                request, spec, ReasonCode.SCOPE_NOT_GRANTED, "Scope is not granted to this tool"
            )
        for arg, patterns in rule.argument_allowlists.items():
            value = request.arguments.get(arg)
            if not isinstance(value, str) or _unsafe_path_like(value):
                return self._deny(
                    request,
                    spec,
                    ReasonCode.ARGUMENT_NOT_ALLOWLISTED,
                    "Argument is not allowlisted",
                    {"argument": arg},
                )
            if not any(fnmatch.fnmatchcase(value, p) for p in patterns):
                return self._deny(
                    request,
                    spec,
                    ReasonCode.ARGUMENT_NOT_ALLOWLISTED,
                    "Argument is not allowlisted",
                    {"argument": arg},
                )
        if spec.risk > policy.max_risk:
            return self._deny(
                request,
                spec,
                ReasonCode.RISK_ABOVE_CEILING,
                "Risk exceeds the policy ceiling",
                {"risk": spec.risk.label, "max_risk": policy.max_risk.label},
            )
        # Approval triggers. A policy can add approval but can never remove these.
        trigger: tuple[ReasonCode, str] | None = None
        if spec.requires_approval:
            trigger = (ReasonCode.APPROVAL_TOOL_DECLARATION, "Tool declaration requires approval")
        elif spec.side_effects == SideEffect.EXTERNAL:
            trigger = (
                ReasonCode.APPROVAL_EXTERNAL_SIDE_EFFECT,
                "External side effects always require approval",
            )
        elif spec.risk == Risk.CRITICAL:
            trigger = (ReasonCode.APPROVAL_CRITICAL_RISK, "Critical risk always requires approval")
        elif spec.risk > policy.max_auto_risk:
            trigger = (ReasonCode.APPROVAL_RISK_THRESHOLD, "Risk is above the automatic threshold")
        elif rule.approval == "required":
            trigger = (ReasonCode.APPROVAL_POLICY_RULE, "Policy rule requires approval")
        if trigger is not None:
            return PolicyDecision(
                Decision.REQUIRE_APPROVAL,
                spec.name,
                request.action,
                request.scope,
                spec.risk,
                trigger[0],
                trigger[1],
            )
        return PolicyDecision(
            Decision.ALLOW,
            spec.name,
            request.action,
            request.scope,
            spec.risk,
            ReasonCode.ALLOWED,
            "Allowed by policy",
        )
