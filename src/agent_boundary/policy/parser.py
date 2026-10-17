"""Fail-closed YAML policy loader that rejects duplicate keys and unknown fields."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agent_boundary.policy.schema import PolicyDocument


class PolicyValidationError(Exception):
    """Raised when a policy file cannot be parsed or fails strict schema validation."""


class UniqueKeySafeLoader(yaml.SafeLoader):
    """Custom YAML SafeLoader that raises an error on duplicate mapping keys.

    Standard PyYAML silently overwrites duplicate keys, which in a security
    policy could silently replace an earlier `deny:` block with a later one.
    """

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                hash(key)
            except TypeError as exc:
                raise PolicyValidationError(
                    "YAML mapping keys must be scalar/hashable"
                ) from exc
            if key in mapping:
                raise PolicyValidationError(
                    f"Duplicate YAML key '{key}' detected at line {key_node.start_mark.line + 1}"
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def load_policy_from_text(raw_yaml: str) -> PolicyDocument:
    """Parse and strictly validate a YAML policy string."""
    try:
        data = yaml.load(raw_yaml, Loader=UniqueKeySafeLoader)
    except yaml.YAMLError as exc:
        raise PolicyValidationError(f"Invalid YAML syntax: {exc}") from exc

    if not isinstance(data, dict):
        raise PolicyValidationError("Policy root must be a YAML mapping/object")

    try:
        doc = PolicyDocument.model_validate(data)
    except ValidationError as exc:
        raise PolicyValidationError(f"Policy schema validation failed:\n{exc}") from exc

    _verify_unique_rule_ids(doc)
    return doc


def load_policy(path: Path) -> PolicyDocument:
    """Read, parse, and validate a policy file from disk."""
    if not path.exists() or not path.is_file():
        raise PolicyValidationError(f"Policy file not found: {path}")
    try:
        raw_yaml = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyValidationError(f"Failed to read policy file {path}: {exc}") from exc
    return load_policy_from_text(raw_yaml)


def _verify_unique_rule_ids(doc: PolicyDocument) -> None:
    """Ensure every rule ID across the entire policy document is unique."""
    seen: set[str] = set()
    all_rule_ids = [
        *(rule.id for rule in doc.filesystem.deny),
        *(rule.id for rule in doc.filesystem.require_approval),
        *(rule.id for rule in doc.filesystem.allow),
        *(rule.id for rule in doc.commands.deny),
        *(rule.id for rule in doc.commands.require_approval),
        *(rule.id for rule in doc.commands.allow),
        *(rule.id for rule in doc.network.deny),
        *(rule.id for rule in doc.network.require_approval),
        *(rule.id for rule in doc.network.allow),
    ]
    for rule_id in all_rule_ids:
        if rule_id in seen:
            raise PolicyValidationError(f"Duplicate rule id '{rule_id}' in policy document")
        seen.add(rule_id)
