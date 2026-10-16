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

Real filesystem isolation, network enforcement, syscall filtering, resource limits, mediated approvals, and adversarial enforcement tests are later milestones and are not implemented by this Phase 1 bundle.
