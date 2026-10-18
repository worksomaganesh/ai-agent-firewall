# Contributing to AI Agent Firewall

Thank you for your interest in contributing to AI Agent Firewall (agent-boundary). Contributions can improve the implementation, tests, documentation, usability, and clarity of this educational security prototype.

Because this project deals with operating-system isolation, network mediation, approvals, and audit evidence, changes need to be especially careful about the difference between an intended policy decision and a control that is actually enforced. A passing test is useful evidence, but it is not a general proof of security.

Please read this document and the project's README before opening a pull request.

## 1. Project scope and principles

agent-boundary is a Linux-first local CLI and security supervisor intended to run coding-agent commands in a constrained environment. The project explores:

- Strict, versioned YAML policy validation and deterministic decisions.
- Bubblewrap-based Linux isolation, process limits, and fail-closed startup.
- Host-side policy enforcement for supported proxy-mediated network requests.
- Scoped human approval for explicitly mediated actions.
- Hash-chained JSONL audit records and verification.
- Private workspace staging, change review, and evidence-preserving workflows.
- Unit, integration, adversarial, and property-based tests.

It is an educational prototype, not production endpoint protection. It has not received an independent professional security audit. Please do not describe a change as preventing all prompt injection, all data exfiltration, all command execution, or all possible sandbox escapes unless the exact claim is narrowly defined and supported by appropriate evidence.

### Design principles

1. **Least privilege:** expose only the workspace paths, capabilities, and network routes needed for a task.
2. **Fail closed:** invalid policy, ambiguous security-sensitive input, or required isolation failures must not silently widen permissions.
3. **Explicit trust boundaries:** distinguish the host supervisor, untrusted child process, kernel sandbox, guest bridge, host proxy, and local evidence files.
4. **Deterministic security decisions:** security-critical policy outcomes should not depend on an LLM's judgement at runtime.
5. **Reviewable evidence:** explain what was observed, what was enforced, and what remains outside the implementation's visibility.
6. **Small, testable changes:** prefer focused changes with clear acceptance criteria and regression tests over broad rewrites.
7. **Honest documentation:** document compatibility limits, failed assumptions, untested paths, and residual risks.

## 2. Before starting a contribution

For non-trivial changes, open or locate an issue before beginning implementation. Describe the problem, intended behavior, affected component, and how success will be tested. For a small documentation typo, an issue may be unnecessary.

For security vulnerabilities, **do not create a public issue containing exploit details**. Follow the private reporting instructions in [SECURITY.md](SECURITY.md). A public pull request should not disclose an unresolved vulnerability without prior coordination.

Before working, check the existing implementation and tests so that the proposed change does not duplicate existing behavior or contradict a documented limitation.

## 3. Development environment

### Prerequisites

- Python 3.11 or newer, consistent with the package metadata.
- Git.
- A virtual environment and permission to install the project's development dependencies.
- For real OS-enforcement tests, a supported Linux environment with a compatible Bubblewrap installation and working user-namespace/kernel configuration.
- Familiarity with the relevant component before modifying security-sensitive code.

The current CI workflow tests Ubuntu 22.04 with Python 3.11 and Ubuntu 24.04 with Python 3.11, 3.12, and 3.13. These are CI-tested combinations, not a guarantee that every Linux distribution, kernel, AppArmor profile, container, or developer machine is supported.

### Clone and install

~~~bash
git clone https://github.com/worksomaganesh/ai-agent-firewall.git
cd ai-agent-firewall

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
~~~

On Windows, the virtual-environment activation command differs, and the real Bubblewrap enforcement backend is not supported there. Use a compatible Linux environment to validate enforcement behavior rather than treating simulation tests as proof of OS isolation.

### Inspect the command surface

~~~bash
agent-boundary --help
agent-boundary --version
agent-boundary validate-policy policies/strict-default.yaml
~~~

Read the README's setup, demo, and security-limitations sections before running a real sandbox command. Use a disposable test repository; do not experiment first on a sensitive working tree.

## 4. Tests and quality checks

Run the checks relevant to your change before opening a pull request.

### Test suite

~~~bash
python -m pytest --cov=agent_boundary --cov-report=term-missing
~~~

### Ruff checks

~~~bash
python -m ruff check --select E4,E7,E9,F src tests
~~~

### Type checks

~~~bash
python -m mypy --follow-imports=silent src/agent_boundary
~~~

### Compile and CLI smoke checks

~~~bash
python -m compileall -q src tests
agent-boundary --help
agent-boundary --version
~~~

The CI workflow also builds the wheel and source distribution, checks package metadata, and installs each artifact in a clean virtual environment. Follow the current workflow as the authoritative source for exact automated checks.

Some tests require Linux kernel features and a usable Bubblewrap environment. If your host cannot execute those tests, state that clearly in the pull request and provide the results you did obtain. **A skipped or unavailable sandbox test is not a passing enforcement test.** Do not weaken or remove an enforcement test solely to make an unsupported host report a green run.

## 5. Testing expectations by change type

### Policy parser, schema, or policy engine

- Add tests for normal behavior and invalid or ambiguous input.
- Verify unknown fields, duplicate YAML keys, invalid rule identifiers, invalid ports, and missing or unmatched rules where relevant.
- Test deny/approval/allow precedence and default-deny behavior when changing evaluation logic.
- Include path normalization, workspace traversal, and symlink-related cases when changing filesystem policy.
- Keep decisions deterministic and reasons sufficiently clear to diagnose a result.

### Bubblewrap, namespaces, Seccomp, or resource limits

- Test successful setup and failure cases.
- Verify that required isolation failure does not silently launch the requested command unsandboxed.
- Add or update Linux enforcement tests that check observed behavior, not only that a command-line argument was constructed.
- Document kernel, namespace, AppArmor, privilege, and resource-limit assumptions.
- Do not claim process-tree-wide resource enforcement unless a process-tree-wide mechanism is implemented and tested.

### Network proxy, guest bridge, or DNS handling

- Test malformed authorities, invalid ports, ambiguous HTTP framing, duplicate or conflicting headers, policy denials, DNS failures, and private or loopback address handling as relevant.
- Ensure invalid requests are rejected before opening an upstream connection.
- Consider DNS changes, IPv4/IPv6 differences, connection cleanup, timeouts, and malformed byte sequences.
- Explain which metadata is visible to the proxy and which TLS payload remains encrypted.
- Do not claim that a hostname allowlist is complete data-loss prevention.

### Approvals and guarded operations

- Test denial, missing terminal or broker, timeout, expiry, reuse, target mismatch, rule mismatch, and target replacement where relevant.
- Keep grants scoped to the intended operation, target, policy rule, and bounded validity period.
- Avoid designs where an approval for one operation can be reused for another.
- Make the denied outcome explicit when approval cannot be safely obtained.

### Audit records and reports

- Test record ordering, sequence continuity, hash recomputation, altered payloads, broken links, and optional HMAC behavior.
- Document whether the head hash is independently anchored and how an HMAC key is supplied and protected.
- Do not call a local hash chain immutable or impossible to tamper with.
- Keep secrets, credentials, tokens, and unnecessary personal data out of events and reports.

### Workspace staging, diffs, and exports

- Test secret-like path exclusions, symlink handling, traversal attempts, overwrite protections, and error cleanup where applicable.
- Confirm that changes are not copied back to the source workspace unexpectedly.
- Use synthetic test files and credentials only.
- Consider partial copies, interrupted operations, and destination paths that already exist.

### Documentation-only changes

- Check commands, filenames, paths, links, and security claims against the current code.
- Clearly distinguish current behavior from planned work.
- Do not update test counts or quote a CI result from a different commit as though it validates the proposed change.

## 6. Coding and review conventions

- Follow the project's existing module structure and naming conventions.
- Prefer small functions with clear inputs, outputs, and error behavior.
- Use type annotations for public functions and security-sensitive interfaces.
- Use the existing Pydantic models for validated policy structures instead of duplicating schema checks in multiple places.
- Preserve useful error context without printing secrets or sensitive local paths unnecessarily.
- Avoid broad exception handling that hides failures or accidentally converts a deny/error into an allow.
- Use explicit constants or enums where they make security-relevant states easier to audit.
- Avoid unnecessary dependencies. Explain the need and maintenance impact of any new runtime dependency.
- Keep public interfaces, policy schema changes, CLI flags, and exit-code changes documented.
- Maintain compatibility intentionally; if a breaking change is necessary, describe its impact and migration path.

Do not reformat or rewrite unrelated modules as part of a narrow security fix unless there is a clear reason.

## 7. AI-assisted development

AI coding tools may be used as part of development, but generated code must be reviewed as carefully as manually written code. The contributor submitting a change remains responsible for its correctness, license compatibility, security impact, tests, and documentation.

Before submitting AI-assisted changes:

- Understand the code path and be able to explain why the implementation is correct.
- Check for invented APIs, incorrect assumptions, unsafe defaults, broad permissions, and silent fallbacks.
- Review generated tests to ensure they assert meaningful outcomes rather than merely exercising code.
- Verify that the change does not contain secrets or copied material whose use is not permitted.
- Disclose substantial AI assistance when it is material to the review or requested by the maintainers.

Do not present generated code, generated test counts, or a model's security claims as independently verified evidence.

## 8. Pull request workflow

1. Fork the repository or create a working branch in an authorized development setup.
2. Keep the change focused and use a descriptive branch name, for example fix/proxy-authority-validation or docs/sandbox-setup.
3. Add or update tests and documentation alongside behavior changes.
4. Run the relevant local checks and record which tests ran, failed, or could not run.
5. Review the diff for accidental changes, secrets, generated artifacts, temporary files, and unrelated formatting.
6. Open a pull request using the repository template. Explain the motivation, implementation, risk, verification evidence, and remaining limitations.
7. Respond to review feedback with follow-up commits and updated test evidence.

Example commit subjects:

- fix: reject ambiguous proxy authority
- test: cover expired approval grants
- docs: clarify sandbox prerequisites

These are examples, not a strict commit-message standard.

## 9. Security disclosure and data handling

- Report suspected vulnerabilities using [SECURITY.md](SECURITY.md), not a public issue or pull request containing exploit details.
- Never commit real API keys, private keys, passwords, access tokens, production logs, customer data, or private repository contents.
- Use synthetic fixtures such as clearly fake tokens and minimal temporary directories.
- If a real secret is accidentally exposed, revoke or rotate it promptly; removing the visible file alone may not remove it from Git history or existing clones.
- Avoid tests that access external systems or send data to real third-party destinations unless that behavior is specifically necessary, authorized, and safely controlled.

## 10. Documentation, release, and compatibility

Documentation changes are part of the implementation, particularly when a security boundary or operational assumption changes. Update relevant README sections, policy examples, release notes, and security evaluation materials as appropriate.

A green local test run does not establish compatibility with all supported operating systems. CI evidence applies to the exact commit and environment that ran it. If a change adds a platform, kernel assumption, dependency, or configuration requirement, update the support documentation and tests rather than implying wider compatibility.

Contributors should not make a production-readiness claim on behalf of the project. The project remains an educational prototype unless the repository explicitly documents a different status backed by appropriate review and evidence.

## 11. Review and acceptance

Maintainers may request changes, additional tests, clearer documentation, or a narrower scope before accepting a contribution. A contribution may be declined if it cannot be reproduced, weakens a security boundary without justification, lacks evidence for a security claim, adds excessive complexity, or falls outside the project's goals.

Opening a pull request does not guarantee acceptance or a specific review timeline. Maintainer availability may vary.

Thank you for helping make agent-boundary more understandable, testable, and responsible.
