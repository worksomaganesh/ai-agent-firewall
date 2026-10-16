# Phase 4 — Adversarial evaluation and release gate

## Purpose

This document records the current security validation strategy for agent-boundary. Passing tests establish behavior only for the checked cases and environment; they are not proof of production security or an independent security audit.

## Validation matrix

| Area | Adversarial cases | Evidence / test location | Boundary still to validate |
|---|---|---|---|
| Policy engine | Unknown operations, unmatched targets, deny-overrides-allow, path traversal | tests/test_phase1_acceptance.py, tests/test_phase1_regressions.py | Fuzz policy schema and normalization combinations |
| Proxy authority parsing | Userinfo, invalid ports, fragments, path suffixes, malformed and single-label names, invalid labels | tests/test_phase4_adversarial.py | Property-based fuzzing and differential HTTP parser testing |
| HTTP request framing | Duplicate Content-Length, Transfer-Encoding, CL+TE, folded headers, invalid header names, oversized header blocks | tests/test_phase4_adversarial.py | Add property-based mutation corpus; keep unsupported framing denied |
| DNS and routing | Unmatched host, private/loopback result, multiple resolved addresses | tests/test_network_proxy.py, tests/test_phase4_adversarial.py | IPv4-mapped IPv6 / unusual resolver record matrix |
| Approval security | Wrong answer, missing broker, expiry, reuse, target/rule mismatch, target replacement during approval | tests/test_approval.py, tests/test_guarded_action_gate.py, tests/test_guarded_workspace_tools.py | TTY behavior on supported terminals and high-concurrency stress |
| Filesystem adapter | Secret denial, traversal, symlink rejection, target fingerprint changes, safe file operations | tests/test_guarded_workspace_tools.py | Directory-fd/openat2 hardening and filesystem race stress |
| Workspace recovery | Export traversal, symlink source, no-overwrite, evidence-preserving discard | tests/test_phase3_workflows.py | Recovery from disk-full, power loss, and interrupted copies |
| OS sandbox | Secret exclusion, no source-tree mount, direct network blocked, proxy bridge reaches policy proxy, rlimits, fail-closed start | tests/test_phase2_sandbox.py | Linux distribution/kernel/AppArmor matrix; descendants/resource aggregation |
| Audit | Hash tampering, chain breaks, sequence gaps and approval-event tampering | tests/test_phase1_acceptance.py, tests/test_phase4_adversarial.py | External anchoring/key custody and filesystem crash durability |
| Build quality | Lint, selected strict type checks, import/CLI smoke checks and full tests | GitHub Actions security-quality job | Full-repository strict mypy cleanup and independent review |

## Newly hardened proxy behavior

The policy proxy now rejects duplicate Content-Length headers, all Transfer-Encoding framing, and CONNECT requests that carry body-framing headers. Until request framing is normalized and tested end-to-end, rejecting these forms is safer than allowing different HTTP parsers to interpret the same byte stream differently. This may reject some legitimate chunked HTTP clients; that is an intentional fail-closed compatibility limitation.

## Residual risks and non-goals

- This repo is a prototype. It has not received an independent professional security audit.
- The Python GuardedActionGate and GuardedWorkspaceTools cover only operations routed through those adapters. They do not intercept arbitrary syscalls or every child-process command.
- Seccomp is a denylist rather than a complete syscall allowlist; kernel-version and syscall behavior varies.
- The proxy sees hostnames and ports for proxied HTTP/HTTPS CONNECT traffic, not encrypted TLS payloads. It cannot stop data exfiltration over an explicitly allowed LLM API.
- Direct socket traffic is blocked by the Linux network namespace, but attempts rejected by the kernel do not necessarily yield per-destination proxy audit events.
- rlimits are inherited per process and do not constitute a cgroup-wide aggregate CPU/memory budget.
- Host audit logs can be replaced by a host user who controls the directory; hash chains need an independently retained head hash or HMAC key to detect full-file re-chaining.
- Workspace staging/export is not an automatic merge or rollback system. Review exported content before copying it to a real repository.

## Release gate (not yet satisfied)

Do not call this a production release until all items are addressed:

- [ ] Run the supported Linux/kernel/AppArmor matrix and publish results.
- [ ] Add property-based/fuzz testing for policy parsing, proxy request parsing and path handling.
- [ ] Run full strict static typing and lint across the entire repository and resolve all failures.
- [ ] Check Python packaging from a clean virtual environment and verify wheel/sdist contents.
- [ ] Perform a threat-model review against the current code, not just the blueprint.
- [ ] Obtain an independent security review.
- [ ] Publish a release checklist, support matrix, known limitations and reproducible test evidence.
