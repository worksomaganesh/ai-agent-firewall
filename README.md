# AI Agent Firewall — agent-boundary

**A Linux-first security supervisor prototype for AI coding agents.**

The aim is to let developers run an AI coding agent inside explicit operating-system boundaries, evaluate outbound HTTP/HTTPS connections against a deterministic policy, and produce an auditable session record. Prompt instructions are not treated as security controls.

> [!CAUTION]
> This is an educational security prototype, not a production-ready endpoint security product. Do not rely on it as the only protection for valuable secrets or a sensitive workstation. Read the limitations below before running an untrusted agent.

## Project progress at a glance

The roadmap contains **5 phases total: Phase 0 plus implementation Phases 1–4**.

| Phase | Goal | Status | Work included |
|---|---|---|---|
| **0 — Architecture and threat model** | Establish assets, trust boundaries, requirements, risks, and architecture | **Complete** | Linux-first design, threat scenarios, backend selection, acceptance criteria |
| **1 — Reliable core** | Build the policy/control plane and audit foundation | **Complete against the current acceptance suite** | Strict YAML schema, deterministic policy engine, simulation, JSONL hash-chain audit, verifier, reports, regression tests and CI |
| **2 — OS isolation and live network policy** | Run commands in a Linux sandbox with static filesystem protections, resource caps, network mediation, audit evidence and diffs | **Complete — latest Linux CI passed** | Bubblewrap namespaces, Seccomp-BPF, rlimits, fail-closed preflight, private workspace copy, host UNIX-socket policy proxy, guest loopback bridge, live network decisions, audit/report integration and enforcement tests |
| **3 — Approvals and recovery** | Add safe, scoped human approvals and review/recovery workflows | **Not started** | Host TTY approval broker, expiring action-bound approvals, target revalidation, safer restore/review flow and guarded tool integrations |
| **4 — Adversarial evaluation and release** | Validate the threat model and prepare a responsible release | **Not started** | Adversarial fixtures, supported-Linux CI matrix, static/type checks, independent review, reproducible demos, release packaging and documented residual risks |

**How much is done?** Phases 0, 1 and 2 are complete: **3 of 5 roadmap phases (60% by phase count)**. That is not a claim that 60% of total engineering effort is finished; the remaining phases include approvals, recovery, wider adversarial evaluation and release hardening. The latest Linux CI run passed **26 tests**, including the real Bubblewrap isolation and guest-to-host proxy bridge test. Phases 3 and 4 have not started. The project is not production-ready.

Check the [successful Linux CI run](https://github.com/worksomaganesh/ai-agent-firewall/actions/runs/38911615189) and the [full Actions history](https://github.com/worksomaganesh/ai-agent-firewall/actions).

## Phase details

### Phase 0 — Architecture and threat model (complete)

- Identified protected assets: host credentials, workspace secrets, Git hooks/configuration, local services, host files, process resources and audit evidence.
- Defined the host supervisor and Linux kernel as trusted components, with the coding agent and its tool outputs treated as untrusted.
- Selected a Linux-first approach using Bubblewrap namespaces, Seccomp-BPF, strict policy validation and auditable session artifacts.
- Documented key limits such as the difference between static filesystem boundaries and interactive approvals, and the fact that HTTPS payloads cannot be inspected by a hostname-only proxy.

### Phase 1 — Reliable core (complete)

- Versioned YAML policy schema that rejects unknown fields and duplicate keys.
- Deterministic policy evaluation with precedence **deny > require approval > allow > default deny**.
- CLI commands for policy validation, action evaluation, simulation, audit verification and reports.
- Mock-agent attack scenarios that do not call an external LLM API.
- JSONL audit records linked with a SHA-256 hash chain and optional HMAC-SHA256.
- Regression tests and GitHub Actions CI.

**Phase 1 is a control plane, not OS enforcement.** A simulated decision is not proof that Linux blocked an action.

### Phase 2 — OS isolation and live network policy (complete)

The current runner is designed to:

1. Require Linux, a trusted root-owned/non-writable/non-setuid Bubblewrap binary, and a successful preflight probe. The current version check requires upstream Bubblewrap 0.12.0 or newer.
2. Create required user, PID, network, IPC and UTS namespaces; drop capabilities and disable further user namespace creation.
3. Apply an architecture-aware Seccomp-BPF denylist and inherited resource limits: CPU time, address-space memory, maximum individual file size, open file descriptors, core dumps, and a wall-clock timeout.
4. Copy the source project into a private session directory rather than mounting the original project writable.
5. Omit common secret-like files and apply filesystem policy read-deny rules during staging. Mount selected write-deny/approval paths read-only where supported.
6. Keep selected Git metadata and GitHub Actions workflow files read-only and sanitize Git configuration/hooks in the staged copy.
7. Clear host environment variables and launch a small guest bridge that listens on loopback inside the sandbox.
8. Forward proxy connections through a mounted host UNIX socket to a host-side policy proxy. Direct TCP/UDP/DNS attempts are blocked by the private network namespace.
9. Evaluate every HTTP request / HTTPS CONNECT destination against the YAML network policy. Unmatched or denied destinations are blocked; require-approval destinations fail closed until Phase 3 provides a real approval broker.
10. Write session audit events, manifests, a workspace diff, a summary and a human-readable report.

#### Install for development

Requirements: Python 3.11+, Linux for real sandbox execution, Bubblewrap 0.12.0+ with working unprivileged user namespaces, and a valid policy file.

~~~bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
~~~

#### Validate a policy

~~~bash
agent-boundary validate-policy policies/strict-default.yaml
~~~

#### Run a command in the sandbox

~~~bash
agent-boundary run \
  --workspace ./my-project \
  --policy ./policies/strict-default.yaml \
  --timeout 600 \
  --memory-mib 4096 \
  -- /bin/sh -c 'pwd; ls -la'
~~~

Session artifacts default to ~/.local/state/agent-boundary/runs/. Set --output-root to a different directory outside the source workspace.

The command runs against a **private staged copy**. Changes are not automatically copied back. Review diff.json and the session report, then manually copy back only the changes you want.

#### Network policy behavior

- Only clients that honor HTTP_PROXY / HTTPS_PROXY use the proxy bridge. Raw network sockets are blocked by the isolated network namespace.
- The proxy evaluates the destination host and port on each HTTP request or HTTPS CONNECT before opening an upstream socket.
- A hostname is resolved on the host only after policy allows it. Non-global, private, loopback, link-local, reserved and metadata-style destinations are denied. The connection is made to the checked address to reduce DNS-rebinding risk.
- HTTPS CONNECT is a tunnel. The proxy does **not** decrypt TLS or inspect encrypted request paths, bodies or prompt contents.
- Network require-approval rules are denied until Phase 3 adds a real interactive approval broker. They are not silently auto-approved.
- Direct socket bypass attempts fail before reaching the proxy and therefore may not create an individual network-request audit event.

#### Resource limits and fail-closed startup

The runner applies per-process Linux rlimits for CPU time, address-space memory, file size, file descriptors and core dumps, plus a supervisor wall-clock timeout. These limits are not the same as a cgroup-wide aggregate budget across all descendants.

The requested command should not start when preflight or sandbox setup fails. Session reports distinguish a sandbox child that started from a setup failure. If Bubblewrap is absent, too old, untrusted or blocked by kernel policy, fix the host configuration rather than falling back to unsandboxed execution.

### Phase 3 — Approvals and recovery (planned)

- Host-side approval prompts reading from a dedicated host terminal, not agent-controlled stdin.
- Expiring approvals bound to a specific action and target, with target-state revalidation immediately before execution.
- Guarded command/tool integrations for operations that can be mediated in user space.
- Human review and recovery support for changes in the private workspace copy.
- Clear separation in logs and reports between kernel-enforced controls, proxy decisions, policy evaluations and unobserved activity.

### Phase 4 — Adversarial evaluation and release (planned)

- Test fixtures for prompt injection, secret discovery, path traversal, symlink tricks, Git-hook persistence, malformed proxy requests, private-IP DNS answers, direct network bypass, resource exhaustion, timeouts and audit corruption.
- Automated tests on supported Linux distributions and Bubblewrap configurations.
- Static analysis, type checks, threat-model review and, ideally, independent security review.
- Reproducible demonstration scripts, release packaging, support matrix, evidence-based documentation and an explicit residual-risk list.

## Tests

Run the suite locally:

~~~bash
python -m pytest --cov=agent_boundary --cov-report=term-missing
~~~

Tests cover policy schema and precedence, audit integrity, fail-closed startup, resource-limit validation, proxy allow/deny decisions, require-approval denial without a broker, private-address rejection, workspace staging/diff evidence, and a real Bubblewrap enforcement test where the host permits it.

A real sandbox test may be skipped when Bubblewrap is missing or unprivileged namespaces are unavailable. A skipped enforcement test is **not** evidence that the security boundary works. Review the current CI run and logs.

## Current limitations — read before use

- **Prototype only.** The project has not had a comprehensive independent security review.
- **Filesystem policy is not a general syscall broker.** Secret exclusion, policy-aware staging and static read-only mounts provide boundaries, but arbitrary file operations are not all intercepted at syscall time.
- **Command policy is not yet a complete live command broker.** Phase 2 enforces the OS sandbox and network policy; it does not guarantee every nested command is evaluated by the command policy engine.
- **Interactive approvals are not implemented.** A network action requiring approval is denied. Filesystem approval rules may be enforced more strictly as read-only mounts.
- **TLS payloads remain opaque.** An allowed LLM API can receive source material in prompts or request bodies; a host/port allowlist cannot prevent that.
- **Resource rlimits are per process.** A cgroup-based aggregate quota remains future hardening work.
- **Proxy-aware applications only.** An app that ignores proxy variables cannot connect directly, but it may fail rather than use the allowed network.
- **Network audit coverage is not total.** Direct socket attempts blocked by the kernel may not appear in proxy logs.
- **Workspace copy requires review.** Original files are not modified by the runner, but manually copying changes back can still introduce harmful code. Review diffs first.
- **Audit anchoring matters.** A hash chain detects many edits, but a person able to replace the entire evidence bundle can recompute the chain unless the final hash or HMAC key is independently retained.
- **Linux-only enforcement.** The real Bubblewrap backend is not available on Windows or macOS.

## Repository structure

~~~text
.
├── README.md
├── pyproject.toml
├── policies/
│   └── strict-default.yaml
├── scenarios/
│   └── mock-agent-attack-suite.json
├── src/agent_boundary/
│   ├── cli.py
│   ├── simulator.py
│   ├── policy/
│   ├── audit/
│   └── sandbox/
│       ├── bwrap.py
│       ├── proxy.py
│       ├── guest_bridge.py
│       ├── seccomp.py
│       ├── snapshot.py
│       └── workspace.py
└── tests/
    ├── test_phase1_acceptance.py
    ├── test_phase1_regressions.py
    └── test_phase2_sandbox.py
~~~

## Security references

- [Bubblewrap README and sandbox security model](https://github.com/containers/bubblewrap/blob/main/README.md)
- [Bubblewrap security advisories](https://github.com/containers/bubblewrap/security/advisories)
- [Linux kernel Seccomp filter documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html)
