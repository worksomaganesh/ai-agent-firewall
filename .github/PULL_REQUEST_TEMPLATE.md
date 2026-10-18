# Pull Request

## 1. Summary

<!-- Describe what changed, why it is needed, and the user-visible result. -->

## 2. Related issue or discussion

<!-- Link a related issue, if one exists. For an undisclosed security vulnerability, coordinate through the private process in SECURITY.md; do not expose details here. -->

Closes #

## 3. Change type

Select all that apply:

- [ ] Bug fix
- [ ] New feature
- [ ] Security hardening
- [ ] Tests or test infrastructure
- [ ] Documentation
- [ ] Refactoring or maintenance
- [ ] Build, packaging, or CI change

## 4. Implementation details

<!-- Identify the affected modules and explain important design decisions. If behavior changed, describe the old and new behavior. -->

## 5. Security and trust-boundary review

- [ ] I considered whether this change affects filesystem access, network access, child processes, sandbox setup, resource limits, approvals, or audit evidence.
- [ ] I have not silently widened permissions or introduced an unsandboxed fallback.
- [ ] Invalid, ambiguous, or unsupported security-sensitive input fails safely.
- [ ] I have considered path traversal, symlinks, DNS/address validation, request parsing, approval scope, or audit tampering where relevant to this change.
- [ ] I have documented residual risks and assumptions rather than making broader claims than the implementation supports.
- [ ] This public pull request does not disclose an unresolved vulnerability or sensitive exploit details.

If a checkbox is not relevant, explain why below rather than checking it without review.

**Security impact and residual risk:**

<!-- State what security property changes, what evidence supports it, and what remains unverified. Write "No intended security impact" only after reviewing the affected path. -->

## 6. Tests and verification evidence

List the exact commands run and their results. Do not report skipped or unavailable tests as passed.

| Check | Run? | Result / notes |
|---|---|---|
| Relevant targeted tests | | |
| Full pytest suite | | |
| Linux Bubblewrap enforcement tests, where applicable | | |
| Ruff | | |
| Full-package mypy | | |
| Compile and CLI smoke checks | | |
| Package/build checks, where applicable | | |

Commands used:

~~~bash
python -m pytest --cov=agent_boundary --cov-report=term-missing
python -m ruff check --select E4,E7,E9,F src tests
python -m mypy --follow-imports=silent src/agent_boundary
python -m compileall -q src tests
agent-boundary --help
agent-boundary --version
~~~

<!-- If the full suite or an enforcement test could not run on your environment, explain the reason and leave the result clearly marked as not run or skipped. -->

## 7. Test coverage added or updated

<!-- Describe the important positive, negative, regression, adversarial, or property-based cases. For security changes, explain what concrete outcome the test asserts. -->

- [ ] Tests cover the intended behavior.
- [ ] Tests cover relevant failure, denial, and malformed-input cases.
- [ ] Tests use synthetic data and do not depend on real credentials or private user information.

## 8. Documentation and compatibility

- [ ] README or relevant documentation has been updated.
- [ ] CLI options, policy schema, error behavior, and exit codes are documented where changed.
- [ ] Security evaluation or release notes have been updated where appropriate.
- [ ] Dependencies, Python compatibility, Linux/kernel requirements, and platform assumptions are documented where changed.
- [ ] Examples and commands have been checked against the implementation.

**Compatibility or migration notes:**

<!-- Describe breaking changes or write "None" if there are none. -->

## 9. Data, generated files, and dependencies

- [ ] No real secrets, tokens, private keys, production logs, customer data, or unrelated generated artifacts are included.
- [ ] New dependencies are necessary and their purpose is explained.
- [ ] Third-party code and assets have appropriate attribution and license compatibility reviewed.
- [ ] I reviewed the final diff and removed unrelated changes.

## 10. AI-assisted development

- [ ] I reviewed the implementation and tests, including any AI-generated material, and can explain the relevant code paths and design decisions.
- [ ] I checked for invented APIs, unsafe assumptions, unverified security claims, and unintended data exposure.
- [ ] Any substantial AI assistance relevant to reviewing this change is disclosed below or in the implementation notes.

**AI-tool or generated-code notes, if relevant:**

<!-- Optional. Disclose material assistance when it affects how reviewers should evaluate the contribution. Do not paste private prompts or secrets. -->

## 11. Final maintainer-facing notes

<!-- Mention limitations, follow-up work, test constraints, rollout concerns, or anything a reviewer should know. -->
