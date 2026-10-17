"""Property-based policy-schema and safe YAML loader tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from hypothesis import given, settings, strategies as st

from agent_boundary.policy.parser import PolicyValidationError, load_policy_from_text

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "strict-default.yaml"
KNOWN_TOP_LEVEL = {
    "schema_version",
    "policy_id",
    "description",
    "workspace_root",
    "default_decision",
    "filesystem",
    "commands",
    "network",
}

json_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**32), max_value=2**32),
    st.text(max_size=48),
)
json_value = st.recursive(
    json_scalar,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=24).filter(lambda key: key != "<<"), children, max_size=4),
    ),
    max_leaves=20,
)


@settings(max_examples=300, deadline=None)
@given(
    extra_key=st.text(max_size=60).filter(
        lambda key: key not in KNOWN_TOP_LEVEL and key != "<<"
    ),
    value=json_value,
)
def test_arbitrary_unknown_top_level_policy_keys_fail_closed(extra_key: str, value: object) -> None:
    baseline = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    baseline[extra_key] = value
    raw = yaml.safe_dump(baseline, sort_keys=False)
    with pytest.raises(PolicyValidationError):
        load_policy_from_text(raw)


@settings(max_examples=300, deadline=None)
@given(port=st.integers(min_value=-100000, max_value=100000))
def test_policy_network_ports_enforce_the_full_valid_range(port: int) -> None:
    baseline = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    baseline["network"]["allow"] = [
        {
            "id": "property-test-port",
            "hosts": ["example.com"],
            "ports": [port],
            "reason": "Generated policy validation test",
        }
    ]
    raw = yaml.safe_dump(baseline, sort_keys=False)
    if 1 <= port <= 65535:
        loaded = load_policy_from_text(raw)
        assert loaded.network.allow[0].ports == [port]
    else:
        with pytest.raises(PolicyValidationError):
            load_policy_from_text(raw)


def test_yaml_unhashable_mapping_keys_are_reported_as_policy_errors() -> None:
    raw = """\
schema_version: "1.0"
policy_id: "unhashable-key"
description: "Malformed YAML policy"
? [unhashable, key]
: dangerous
"""
    with pytest.raises(PolicyValidationError, match="mapping keys must be scalar/hashable"):
        load_policy_from_text(raw)
