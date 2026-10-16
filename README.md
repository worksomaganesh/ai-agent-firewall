# AI Agent Firewall — agent-boundary

**Phase 1: Reliable Core / Control Plane**

A Linux-first policy-evaluation CLI prototype for exploring safer AI coding-agent workflows. Phase 1 includes strict YAML policy validation, deterministic policy decisions, simulation scenarios, hash-chained JSONL audit logs, audit verification, and session reports.

> [!IMPORTANT]
> **Phase 1 is not an OS-enforced firewall.** The `evaluate` and `simulate` commands evaluate policy logic only. They do not place an agent in a Bubblewrap sandbox, prevent filesystem access, restrict network connections, or mediate real commands. Do not rely on this phase to protect secrets when running an untrusted agent.

## Requirements
- Python 3.11+
- pip

## Install for development
```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Quick start
```bash
agent-boundary validate-policy policies/strict-default.yaml
```

Run the deterministic mock-agent scenario in **simulation mode**:
```bash
agent-boundary simulate \
  --policy policies/strict-default.yaml \
  --scenario scenarios/mock-agent-attack-suite.json \
  --output-dir artifacts/demo-session
```

Verify a simulation audit log:
```bash
agent-boundary verify-audit artifacts/demo-session/audit.jsonl
```

Evaluate one action (policy evaluation only; does not execute it):
```bash
agent-boundary evaluate \
  --policy policies/strict-default.yaml \
  --category filesystem \
  --operation read \
  --target /workspace/src/app.py
```

Run acceptance tests:
```bash
pytest
```

## Project structure
- `src/agent_boundary/policy/` — schema, YAML parser, policy engine.
- `src/agent_boundary/audit/` — structured events, JSONL logger, verifier, reports.
- `src/agent_boundary/simulator.py` — deterministic mock-agent simulation.
- `policies/` — example policy.
- `scenarios/` — expected outcomes for normal and attack-shaped actions.
- `tests/` — Phase 1 acceptance tests.

## Current guarantees and limitations
The policy engine implements deny-overrides-approval-overrides-allow precedence and a default-deny fallback for unmatched actions. Audit hash chaining makes many modifications detectable, but strong post-run tamper evidence requires a trusted expected head hash or HMAC key. Simulation logs show what the policy engine decided; they are **not evidence that an operating-system control blocked an action**.

## Phase 2: Linux Bubblewrap runner (initial increment)

The Linux-only run command executes a command in a Bubblewrap user/PID/network/IPC/UTS namespace, applies an architecture-checked Seccomp-BPF denylist and process resource limits, and provides only read-only system executable/library paths plus a sanitized private project copy. Existing .env-like files, common key/credential files, Git hooks, Git remotes/configuration, and nested Git metadata are omitted or sanitized in that copy. Existing Git metadata and GitHub Actions workflows are mounted read-only. Host environment variables are cleared; outbound networking is disabled entirely. The original workspace is not modified: inspect the retained copy and diff in the session directory, then manually apply changes you want to keep.

Bubblewrap 0.12.0 or newer is required. The runner checks for a root-owned, non-writable, non-setuid binary in a trusted system directory and runs a preflight sandbox probe. If a required namespace or seccomp filter cannot be installed, the target command is not launched. The conservative version check may reject distribution packages that backport fixes while reporting an upstream version below 0.12.0.

Example on Linux after installing the package and a trusted Bubblewrap >= 0.12.0:

    agent-boundary run --workspace ./my-project -- /bin/sh -c 'pwd; ls -la'

Session artifacts are written under ~/.local/state/agent-boundary/runs by default. You can choose an alternative parent with --output-root, but it must be outside the source workspace. A run creates an audit.jsonl hash chain, session_report.md, before/after manifests, diff.json, and a retained workspace copy.

Phase 2 limitation: this first increment intentionally has no outbound proxy, no per-action live policy mediation, no interactive approval broker, and no cgroup-based limits. Coding agents that require an external LLM API cannot connect while networking is disabled. Read-only mounts plus staging protect the original project from direct writes, but this does not yet establish a complete agent firewall or prevent all data from being copied out through manually applied staged changes. This project is a security prototype, not a substitute for a reviewed isolation platform.
