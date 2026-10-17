# Phase 4 release checklist and support statement

## Current release classification

**Status: automated test gate passing on the last recorded run; educational prototype only.**

The project is not certified or recommended as a production endpoint security boundary. Automated tests validate known scenarios, not every possible kernel behavior, attack path, or agent integration. No independent professional security audit has been completed.

## CI evidence

- Linux acceptance and enforcement tests: Ubuntu 22.04 and Ubuntu 24.04.
- Runtime compatibility matrix: Python 3.11 on Ubuntu 22.04/24.04; Python 3.12 and 3.13 on Ubuntu 24.04.
- Static checks: Ruff, strict mypy across `src/agent_boundary`, compile/import checks, CLI smoke checks.
- Packaging: wheel and source distribution, `twine check`, clean virtual-environment installation and CLI/import smoke tests for both artifacts.
- Adversarial tests: malformed proxy authorities and HTTP framing, duplicate/ambiguous headers, DNS rebinding/private-address checks, bounded Hypothesis tests for proxy parsing and workspace paths, generated policy schema inputs and invalid port ranges.
- Enforcement tests: Bubblewrap namespaces, direct network isolation, secret/path restrictions, resource limits, fail-closed setup and session evidence, where the CI host supports the required Linux features.

The latest successful workflow run linked from the README passed **93 tests in each of four configurations**: Ubuntu 22.04/Python 3.11 and Ubuntu 24.04/Python 3.11, 3.12 and 3.13. The static/type/package job also passed. See the [run record](https://github.com/worksomaganesh/ai-agent-firewall/actions/runs/38987554557). The Actions run is the authoritative record for exact commit, test count, skipped tests, and job outcomes. Do not copy a passing result to a different commit.

## Supported / tested environments

| Environment | CI coverage | Claim |
|---|---|---|
| Ubuntu 22.04, Python 3.11 | Full suite including Linux sandbox tests | Tested in CI only |
| Ubuntu 24.04, Python 3.11 | Full suite including Linux sandbox tests | Tested in CI only |
| Ubuntu 24.04, Python 3.12 | Full suite including Linux sandbox tests | Tested in CI only |
| Ubuntu 24.04, Python 3.13 | Full suite including Linux sandbox tests | Tested in CI only |
| Other distributions / kernels / AppArmor profiles | Not covered by this matrix | Unverified |
| macOS / Windows | No Bubblewrap enforcement backend | Not supported for real OS enforcement |

CI can adjust user-namespace/AppArmor settings on ephemeral runners. That does not mean the same settings or preflight outcome will hold on a developer's machine.

## Required before any production claim

- [ ] Independent security review of the current implementation and threat model.
- [ ] Additional kernel versions, distribution releases, AppArmor profiles, and constrained-host tests.
- [ ] Longer-running fuzz/stress testing, including policy schema, HTTP parser differential tests, approval concurrency, filesystem races, interruption, disk-full and crash recovery.
- [ ] Validate process-tree resource aggregation; current `rlimit` controls are not cgroup-wide aggregate quotas.
- [ ] Independently anchor audit head hashes or define key custody for HMAC use.
- [ ] Review the exact scope of file and command enforcement. Guarded adapters only protect operations routed through them; they do not intercept every arbitrary syscall or child process.
- [ ] Complete a release threat-model review against the current code and all remaining mitigations.
- [ ] Publish versioned artifacts, checksums, a support matrix, known limitations, and a reproducible release record.
- [ ] Require a human maintainer to review and approve release contents.

## Safe interpretation of results

- A passing unit test proves only the tested behavior.
- A skipped sandbox test is not a passing enforcement test.
- A green CI run does not prove production security.
- Network policy observes proxy-routed HTTP requests and HTTPS CONNECT destinations; it does not decrypt TLS or stop exfiltration to explicitly allowed APIs.
- A host user able to replace the complete audit bundle can re-chain an unsigned hash log unless the final anchor or HMAC key is independently protected.
- Review staged workspace diffs before exporting changes. The tool does not automatically merge results into the original project.
