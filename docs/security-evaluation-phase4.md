# Phase 4 — Adversarial evaluation and release gate

## Purpose

This document records the current security validation strategy for agent-boundary. Passing tests establish behavior only for the checked cases and environment; they are not proof of production security or an independent security audit.

## Validation matrix

| Area | Adversarial cases | Evidence / test location | Boundary still to validate |
|---|---|---|---|
| Policy engine | Unknown operations, unmatched targets, deny-overrides-allow, path traversal | tests/test_phase1_acceptance.py, tests/test_phase1_regressions.py | Property-based malformed-authority, host-normalization, path-normalization, and policy-schema tests run in CI |
| Proxy authority parsing | Userinfo, invalid ports, fragments, path suffixes, malformed and single-label names, invalid labels | tests/test_phase4_adversarial.py | 500-example Hypothesis authority and header-input runs per CI job; differential HTTP parser testing remains future work |
| HTTP request framing | Duplicate Content-Length, Transfer-Encoding, CL+TE, folded headers, invalid header names, oversized header blocks | tests/test_phase4_adversarial.py | Add property-based mutation corpus; keep unsupported framing denied |
| DNS and routing | Unmatched host, private/loopback result, multiple resolved addresses | tests/test_network_proxy.py, tests/test_phase4_adversarial.py | IPv4-mapped IPv6 and mixed public/private DNS answers have explicit regression tests; unusual resolver records remain future work |
| Approval security | Wrong answer, missing broker, expiry, reuse, target/rule mismatch, target replacement during approval | tests/test_approval.py, tests/test_guarded_action_gate.py, tests/test_guarded_workspace_tools.py | TTY behavior on supported terminals and high-concurrency stress |
| Filesystem adapter | Secret denial, traversal, symlink rejection, target fingerprint changes, safe file operations | tests/test_guarded_workspace_tools.py | Directory-fd/openat2 hardening and filesystem race stress |
| Workspace recovery | Export traversal, symlink source, no-overwrite, evidence-preserving discard | tests/test_phase3_workflows.py | Recovery from disk-full, power loss, and interrupted copies |
| OS sandbox | Secret exclusion, no source-tree mount, direct network blocked, proxy bridge reaches policy proxy, rlimits, fail-closed start | tests/test_phase2_sandbox.py | Linux distribution/kernel/AppArmor matrix; descendants/resource aggregation |
| Audit | Hash tampering, chain breaks, sequence gaps and approval-event tampering | tests/test_phase1_acceptance.py, tests/test_phase4_adversarial.py | External anchoring/key custody and filesystem crash durability |
| Build quality | Ruff, full-package strict mypy, import/CLI smoke checks, artifact validation, clean installs and full tests | GitHub Actions matrix and security-quality job | Longer fuzz/stress campaigns, broader runtime matrix and independent review |

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

## Release gate (automated checks pass; external sign-off remains)

Do not call this a production release until all items are addressed:

- [x] Run automated acceptance and sandbox-enforcement CI on Ubuntu 22.04 and Ubuntu 24.04; publish per-job results.
- [ ] Expand the matrix to additional kernel versions, AppArmor configurations, and other supported Linux distributions.
- [x] Add bounded Hypothesis property tests for malformed authorities, host normalization, HTTP header bytes, port ranges, and guarded workspace path traversal.
- [x] Add bounded property-based policy-schema tests for arbitrary unknown fields, generated port ranges, and malformed YAML mapping keys.
- [ ] Run longer fuzzing and differential parser testing; current Hypothesis runs are bounded CI checks, not a long-running fuzz campaign.
- [x] Run repository-wide Ruff checks and selected strict typing for guarded-action/workspace adapters.
- [x] Extend strict mypy checks across the full `src/agent_boundary` package; all package modules pass.
- [x] Build wheel and source distribution, run `twine check`, and install each artifact in a clean virtual environment outside the checkout.
- [ ] Perform a threat-model review against the current code, not just the blueprint.
- [ ] Obtain an independent security review.
- [x] Publish a release checklist, support matrix, known limitations and reproducible test evidence.


## Automated release-gate status

The latest successful workflow run for commit `efbb96c0a82f5d6cb58804340fa4b8fbd4455e39` passed all five jobs: **93 tests passed** on each of four combinations (Ubuntu 22.04/Python 3.11; Ubuntu 24.04/Python 3.11, 3.12, and 3.13), and the static/type/CLI/package job passed. The quality job includes repository-wide Ruff, strict mypy across all package modules, wheel and source-distribution builds, metadata checks, and clean isolated installs. See [the successful workflow run](https://github.com/worksomaganesh/ai-agent-firewall/actions/runs/38987554557).

The automated Phase 4 implementation gate is complete for this matrix. Remaining release blockers are intentionally not represented as passing: independent security review, longer fuzz/stress and differential-parser campaigns, additional kernel/distribution/AppArmor combinations, and a complete code-based threat-model review. Passing CI does not prove production security. This repository remains an educational prototype.
