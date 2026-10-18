# Security Policy

## 1. Purpose and security posture

AI Agent Firewall (agent-boundary) is a Linux-first, educational security prototype for running AI coding-agent commands inside a constrained environment. It explores policy-based decisions, Bubblewrap-based isolation, mediated network access, scoped approvals, audit evidence, and reviewable workspace changes.

**This project is not production endpoint protection and has not received an independent professional security audit.** Automated tests cover known scenarios and environments; they do not establish that every attack path is prevented. Please read the Security Model and Limitations section of the README before relying on the project.

This policy explains how to report a potential vulnerability responsibly. It does not promise a response time, fix deadline, service-level agreement, or production support.

## 2. Scope

Security reports are particularly useful when they demonstrate a reproducible way to violate a documented security boundary or a meaningful security invariant, such as:

- Accessing host files or paths that the configured sandbox is intended to exclude.
- Bypassing a policy decision or reaching an outbound network destination that should be blocked by the documented configuration.
- Causing a mediated request to reach an upstream destination before request validation or policy checks complete.
- Exploiting a path, symlink, approval-scope, or time-of-check/time-of-use issue in an operation that the project explicitly claims to guard.
- Causing an audit chain or verification result to report valid evidence after a record has been altered, under the stated verification assumptions.
- Bypassing fail-closed behavior so the requested command runs without the required sandbox being established.
- Triggering a security-relevant denial-of-service condition in the local tool that exceeds the documented resource and failure assumptions.

Reports about other issues may still be valuable. If uncertain whether a behavior is security-relevant, ask through a private reporting route rather than publishing exploit details.

### Scope boundaries and known limitations

The project explicitly documents that:

- It is an educational prototype, not a certified or independently audited security product.
- Guarded-action and workspace adapters protect only operations routed through those adapters; they do not intercept every arbitrary syscall or every child-process command.
- The Seccomp filter is not a complete syscall allowlist.
- The proxy can inspect destinations and policy-relevant metadata for traffic it mediates, but it does not decrypt TLS payloads.
- An allowed external destination can still receive data sent by an agent.
- Per-process resource limits are not a process-tree-wide aggregate resource budget.
- A locally stored hash chain can be replaced and recomputed by an attacker who controls the entire evidence bundle unless an independent trust anchor or protected key is available.
- Linux distribution, kernel, user-namespace, and AppArmor behavior vary; CI results do not establish compatibility or security on every host.

These limitations are not blanket reasons to dismiss a report. A report may still be valid if actual behavior contradicts the documented boundary, exposes a more serious impact, or reveals that a stated limitation is inaccurate.

## 3. How to report a vulnerability privately

**Please do not publish an exploitable vulnerability, sensitive proof of concept, secret, or detailed bypass steps in a public GitHub issue or pull request.**

1. Open the repository's [GitHub Security area](https://github.com/worksomaganesh/ai-agent-firewall/security) and check whether private vulnerability reporting or a security advisory reporting option is available. If it is available, use that private route.
2. If no private reporting option is available, contact the maintainer through a contact method publicly listed on the maintainer's GitHub profile and ask for a private reporting channel. Do not include exploit details in the initial public message.
3. If you cannot find a private route, do not post sensitive technical details publicly. You may open a non-sensitive issue asking how to reach the maintainer privately, without naming the exact bypass or attaching a proof of concept.

The availability of GitHub private vulnerability reporting depends on repository settings; this document does not claim that feature is currently enabled.

## 4. What to include in a report

Please provide as much of the following as can be shared safely:

- A concise description of the suspected vulnerability and its security impact.
- The affected commit SHA, tag, or version, if known.
- Operating system and distribution, kernel version, Python version, and Bubblewrap version.
- The policy configuration and command needed to reproduce the behavior, with secrets and identifying data removed.
- Minimal, repeatable reproduction steps using a disposable local test directory.
- Expected behavior and actual observed behavior.
- Relevant, redacted error messages, audit events, reports, or test output.
- Any assumptions or environmental prerequisites.
- A suggested mitigation, if you have one; a complete fix is not required to report an issue.

A good report makes it possible to distinguish an actual security-boundary failure from a configuration issue, unsupported environment, or behavior that is already documented as a limitation.

## 5. Safe testing and disclosure

- Test only in an environment you own or have explicit permission to assess.
- Use disposable repositories and synthetic credentials. Never use real production credentials, private customer data, or valuable host files in a proof of concept.
- Do not attempt to access, modify, or exfiltrate data belonging to another person or organization.
- Do not perform destructive testing on a shared machine or a production system.
- Avoid broad scans, denial-of-service experiments, or tests against third-party services.
- Share only the minimum evidence needed to demonstrate the issue.
- Coordinate public disclosure with the maintainer where practical. Do not assume a fix or disclosure date has been agreed until it is explicitly confirmed.

This is a request for responsible testing and coordination, not a grant of legal authorization or a guarantee of legal safe harbor.

## 6. Triage and remediation

When a report is received, the maintainer may attempt to:

1. Reproduce it against the reported commit and a controlled environment.
2. Identify the affected component, required assumptions, impact, and practical attack path.
3. Determine whether the issue violates documented behavior, is a known limitation, or requires clarification in the documentation.
4. Develop and test a mitigation or fix where feasible.
5. Update tests, documentation, and release notes as appropriate.
6. Coordinate disclosure and credit with the reporter, if desired and agreed.

This is the intended process, not a guaranteed timeline or promise that every report will result in a code change. The project is maintained as an educational prototype, and maintainer availability may vary.

## 7. Third-party dependencies and related projects

If a suspected vulnerability is primarily in an upstream dependency, operating system, kernel, or external AI coding agent, report it to the relevant upstream maintainers as well. Please still let this project know privately if you can demonstrate that agent-boundary uses the dependency in a way that creates an additional vulnerability in this project.

Do not assume that a fix in an upstream dependency automatically fixes every affected configuration here. The exact dependency version and execution environment matter.

## 8. Secrets and personal data

Never include live API keys, access tokens, passwords, private keys, personal data, or unredacted sensitive project files in public issues, pull requests, logs, screenshots, or test fixtures. If a real credential may have been exposed, revoke or rotate it promptly; deleting a visible copy does not guarantee that it is absent from repository history, caches, or copies already made.

## 9. Supported versions and release expectations

The repository's default branch is the main development line. Consult the README, release checklist, and the exact CI run for the commit under review to understand the current implementation and tested environment. No long-term support guarantee is made for old commits or untagged snapshots.

Passing CI is evidence about the tested cases and configurations only. It is not proof of production security, complete attack prevention, or an independent security assessment.
