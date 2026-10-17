# AI Agent Firewall — agent-boundary

**A Linux-first, local security supervisor for AI coding agents.**

agent-boundary is a command-line prototype that runs a coding agent inside a Bubblewrap-based Linux sandbox, applies a deterministic policy to mediated network requests, supports scoped host-terminal approvals, and records a reviewable session trail. It is designed around one principle: **a prompt is not a security boundary**. Model instructions can be useful, but filesystem isolation, network isolation and process restrictions must be enforced by operating-system controls.

> [!CAUTION]
> **Educational security prototype — not production endpoint protection.** Do not rely on this project as the only protection for important credentials, a sensitive workstation or production infrastructure. It has automated tests, but has not received an independent professional security audit. Read [Security limitations](#security-limitations-and-residual-risk) before running an untrusted agent.

[Latest successful automated CI run](https://github.com/worksomaganesh/ai-agent-firewall/actions/runs/38987741089) · [Phase IV security evaluation](docs/security-evaluation-phase4.md) · [Release checklist](docs/release-checklist.md)

---

## 1. Project profile

| Attribute | Description |
|---|---|
| **Category** | AI-agent security, application security, developer tooling, Linux sandboxing, local security automation |
| **Difficulty** | Advanced to very advanced. A good learning project after you are comfortable with Python, Linux, subprocesses, networking and automated testing. |
| **Primary user** | A developer running a local AI coding agent against a software repository |
| **Deployment model** | Local CLI and local child processes on Linux; no hosted control plane or cloud database |
| **Primary outcome** | Run a command in a constrained environment and collect evidence about policy decisions, network activity observed by the proxy and workspace changes |
| **Core technologies** | Python 3.11+, Bubblewrap, Linux namespaces, Seccomp-BPF, UNIX domain sockets, HTTP proxying, YAML, Pydantic, pytest, Hypothesis, Ruff, mypy and GitHub Actions |
| **Interface** | Terminal CLI, YAML policy files, HTTP/HTTPS proxy protocol inside the sandbox, local JSON/JSONL session artifacts |
| **Current maturity** | Educational prototype with a passing automated CI matrix; independent security review and wider platform validation remain outstanding |
| **Project style** | Local security supervisor/control plane with an OS-enforced sandbox and host-side mediation components |

### Engineering areas covered

- **Python systems engineering:** package layout, CLI design, validation, subprocess lifecycle and filesystem handling.
- **Operating-system security:** user, PID, network, IPC and UTS namespaces; mount boundaries; Seccomp-BPF; resource limits.
- **Application security:** least privilege, deny-by-default rules, protected paths, trust boundaries, approvals and threat modeling.
- **Networking:** HTTP proxy request parsing, HTTPS CONNECT tunneling, UNIX-socket IPC, DNS resolution and private-address rejection.
- **Evidence and observability:** append-only JSONL audit events, SHA-256 hash chaining, optional HMAC, workspace manifests, diffs and reports.
- **Software quality:** unit, integration, adversarial and property-based tests; linting, strict type checks, clean package builds and CI.

## 2. The problem this project addresses

### The real problem statement

AI coding agents can read project files, edit source code, run commands, install dependencies and contact external services. A malicious issue, repository file, dependency message, generated output or prompt injection can try to persuade an agent to do something outside the developer's intent.

Examples include:

- Reading a project’s .env file or a private key while investigating a bug.
- Sending source code or configuration to an unapproved destination.
- Modifying Git hooks so code executes later on the developer’s host.
- Editing CI workflows or package configuration in a way that persists beyond the current session.
- Deleting or rewriting work with a destructive shell or Git command.
- Attempting to reach localhost services, cloud metadata endpoints, private networks or host files.
- Leaving the developer unsure which files changed, which network requests were allowed or denied, or whether the sandbox actually started.

Prompt instructions such as “do not read secrets” are not sufficient. A compromised agent or a malicious tool result can ignore those instructions.

### Who faces this problem?

| Persona | Need |
|---|---|
| **End user — software developer** | Let a coding agent work on a project without giving it unrestricted access to the host machine |
| **Operator — session owner** | Choose a policy, start a bounded session, respond to approval prompts and inspect results |
| **Administrator — workstation owner** | Understand what isolation the machine supports and avoid unsafe fallback behavior |
| **Security engineer / reviewer** | Inspect policy rules, adversarial tests, audit evidence and documented residual risks |
| **Project maintainer** | Keep the policy engine deterministic, preserve fail-closed behavior, test regressions and review changes |
| **CI runner / test service** | Reproduce policy, parser, packaging and Linux sandbox tests on known environments |
| **Agent process and child tools** | Work within a staged project copy, use the configured proxy for network access and receive a bounded runtime environment |
| **Host-side supervisor** | Set up isolation, mediate approved network traffic, gather evidence, handle approvals and finalize reports |
| **External systems** | DNS resolver and explicitly permitted HTTP/HTTPS destinations such as a configured LLM API or package registry |

The same developer may fill several roles. The table separates responsibilities, not necessarily different people.

### Why does the problem matter?

An agent can be productive and still make a harmful change. The risk is not only that the model produces incorrect code; the agent has tools that can turn a bad instruction into a real filesystem, process or network action.

This project explores **defense in depth**:

1. Do not expose host resources to the agent unless needed.
2. Put OS-enforced boundaries around the child process.
3. Block direct networking from the sandbox and mediate proxy-routed requests.
4. Ask for explicit human approval for supported actions that require it.
5. Keep a record that can be inspected after the session.
6. Test the controls with malicious-looking inputs instead of trusting a happy-path demo.

### Proposed solution

agent-boundary is a local supervisor and CLI. It validates a versioned YAML policy, creates a private copy of a project, starts the requested command inside a Bubblewrap sandbox, mediates proxy-routed HTTP/HTTPS destinations through a host-side policy proxy, records session evidence and leaves the changes for human review.

### How it solves the original problem

| Problem | Intended control | Evidence produced | Important limit |
|---|---|---|---|
| Agent can see unrelated host files | Bubblewrap creates a constrained mount view; the original project is staged into a private copy | Sandbox preflight result and session artifacts | Actual host/kernel policy determines whether isolation can start |
| Agent tries to read common in-workspace secrets | Secret-like paths are excluded or masked during staging; policy-aware tools deny protected paths | Policy decisions and workspace manifests/diff | Not a universal syscall-level file broker; pattern and staging limitations must be considered |
| Agent tries direct network access | Private network namespace removes ordinary external network access; supported proxy traffic is sent through the bridge | Network-proxy decision events | Kernel-blocked raw sockets may not generate per-destination proxy audit events |
| Agent contacts an unapproved HTTP/HTTPS destination | Host-side policy proxy evaluates host and port before connecting | NETWORK_REQUEST audit events | HTTPS content is not decrypted; hostname/port control cannot prevent exfiltration to a destination explicitly allowed for legitimate work |
| Agent wants to change a protected item through a guarded tool | Policy gate can deny or request a scoped host-terminal approval | Approval requested/granted/denied/consumed/revoked events | Applies only to actions explicitly routed through the guarded adapter |
| Agent deletes or modifies work | Session runs against a staged copy; snapshot and diff artifacts support review | Baseline/final manifests, diff and report | No automatic semantic merge or universal rollback system |
| Logs might be modified after the run | Audit records are hash chained and can optionally use HMAC | Audit verification output and final head hash | Independent storage of the final anchor/key is needed to detect replacement of the complete evidence bundle |

## 3. MVP boundary

The MVP is the smallest useful end-to-end local security workflow—not a promise to intercept every operation that any agent might perform.

### Included in the current implementation

- A Python package and agent-boundary CLI.
- Strict versioned YAML policy validation, including unknown-field and duplicate-key rejection.
- Deterministic policy evaluation with **deny > require approval > allow > default deny** precedence.
- A clearly labelled simulation mode for mock scenarios.
- Bubblewrap preflight, sandbox construction, Linux namespaces, Seccomp-BPF and per-process resource limits.
- Private workspace staging, manifests, diffs and session summaries.
- A host policy proxy and a guest-side loopback-to-UNIX-socket bridge.
- Network allow/deny/approval decisions, public-address checks and fail-closed proxy parsing.
- Host-terminal approval grants for supported network and explicitly mediated actions.
- Guarded workspace read/write/delete helpers.
- Hash-chained JSONL audit logs, optional HMAC support, verification and report generation.
- Review, export and discard commands for staged changes.
- Adversarial/property-based tests and automated CI/package checks.

### Explicitly outside the current MVP

- A web dashboard, SaaS control plane, hosted database or remote policy service.
- A cross-platform security backend for macOS or Windows.
- Universal interception of every filesystem syscall, command, child process, MCP tool or agent plugin.
- A full command execution broker that automatically gates every nested shell command.
- TLS interception, payload inspection or data-loss prevention for encrypted traffic.
- A universal secrets manager or safe automatic injection of all LLM API credentials.
- Cgroup-wide aggregate quotas for all descendant processes.
- Automatic merging of agent changes into the original repository.
- A claim that hash chaining alone prevents a privileged host user from replacing all logs and recomputing the chain.
- Certification as a production endpoint-security product.

This boundary matters: **an implemented policy engine is not the same thing as universal runtime enforcement**. OS controls enforce the sandbox boundary; proxy and guarded APIs only see the operations that actually reach them.

## 4. System architecture

### 4.1 Architecture at a glance

The application is organized as a local supervisor with several components in one Python package, plus a child agent process and a small guest bridge. The trust boundary is the Linux kernel and the sandbox configuration—not the agent’s prompts.

~~~mermaid
flowchart TB
    User["Developer / Operator"]
    CLI["agent-boundary CLI"]
    Policy["Strict YAML Loader + Pydantic Schema"]
    Engine["Deterministic Policy Engine"]
    Session["Session Manager / Workspace Stager"]
    Builder["Bubblewrap Builder + Preflight"]
    Kernel["Linux Kernel Enforcement<br/>mount, PID, network, IPC, UTS namespaces<br/>Seccomp-BPF + resource limits"]
    Agent["Untrusted Agent / Child Commands<br/>private /workspace copy"]
    Guest["Guest Proxy Bridge<br/>sandbox loopback TCP listener"]
    HostSocket["Mounted UNIX Domain Socket"]
    Proxy["Trusted Host Policy Proxy"]
    Approval["Host /dev/tty Approval Broker"]
    DNS["Host DNS Resolution"]
    Remote["Permitted Remote Destination"]
    Audit["Host-side Audit Logger<br/>JSONL + SHA-256 chain / optional HMAC"]
    Snapshot["Baseline / Final Manifest + Diff"]
    Report["Session Summary + Human-readable Report"]
    Review["Human Review / Export / Discard"]

    User --> CLI
    CLI --> Policy
    Policy --> Engine
    CLI --> Session
    Session --> Snapshot
    Session --> Builder
    Builder --> Kernel
    Kernel --> Agent
    Agent --> Guest
    Guest --> HostSocket
    HostSocket --> Proxy
    Proxy <--> Engine
    Proxy -->|requires approval| Approval
    Proxy -->|policy permits| DNS
    DNS --> Remote
    Engine --> Audit
    Proxy --> Audit
    Approval --> Audit
    Agent --> Snapshot
    Snapshot --> Report
    Audit --> Report
    Report --> Review
    Review -.->|export only after review| User
~~~

**Trust interpretation:** the host supervisor and kernel enforcement configuration are trusted components. The agent, its child processes, repository content, tool output and generated patches are treated as untrusted. The diagram is conceptual; it does not imply that every arbitrary agent action passes through the Python policy engine.

### 4.2 Architecture responsibilities

| Component | Responsibility | Trust / boundary |
|---|---|---|
| CLI | Parse user intent and present outcomes | Host-side control plane |
| YAML parser and schema | Reject malformed, duplicate-key, unknown-field or unsupported policy input | Host-side configuration boundary |
| Policy engine | Produce deterministic decisions for supported action requests | In-process API; decision making is not itself an OS restriction |
| Workspace stager / snapshotter | Create a private working copy and calculate before/after evidence | Host-side setup and reporting |
| Bubblewrap builder | Construct namespace, mount, seccomp and process configuration | Requests kernel-enforced boundaries |
| Linux kernel | Enforce mount visibility, namespace separation, syscall filter and inherited resource limits | Primary OS boundary |
| Agent and subprocesses | Execute the requested coding task within the sandbox | Untrusted |
| Guest bridge | Accept proxy requests on sandbox loopback and forward bytes through the mounted UNIX socket | Sandbox-side transport helper |
| Host proxy | Parse the request, evaluate the destination, resolve/validate addresses, request approval where applicable and open allowed upstream connections | Trusted mediation component |
| Approval broker | Request explicit confirmation using the host controlling terminal and issue scoped, expiring, one-use grants | Host-side human gate |
| Audit logger and verifier | Write/verify ordered records and hash continuity | Evidence mechanism; not immutable storage against a host administrator |
| Report/review tools | Summarize decisions and staged changes; provide safe export/discard flows | Human review surface |

### 4.3 Data flow: a session from start to finish

~~~mermaid
sequenceDiagram
    actor Dev as Developer
    participant CLI as CLI / Supervisor
    participant Policy as Policy Parser + Engine
    participant Stage as Workspace Stager
    participant Bwrap as Bubblewrap + Kernel
    participant Agent as Agent Process
    participant Bridge as Guest Bridge
    participant Proxy as Host Policy Proxy
    participant TTY as Host Approval Broker
    participant Audit as Audit / Report

    Dev->>CLI: run --workspace ... --policy ... -- command
    CLI->>Policy: Load and validate YAML
    Policy-->>CLI: Validated policy or fail closed
    CLI->>Stage: Create private staged workspace + baseline manifest
    Stage-->>CLI: Session directory and staged copy
    CLI->>Bwrap: Preflight, build sandbox args, set limits
    Bwrap-->>CLI: Start confirmed or setup failure
    Bwrap->>Agent: Execute command inside sandbox

    opt Agent sends HTTP or HTTPS proxy request
        Agent->>Bridge: Request on sandbox loopback proxy
        Bridge->>Proxy: Forward over mounted UNIX socket
        Proxy->>Policy: Evaluate host:port
        alt Policy denies
            Policy-->>Proxy: DENY
            Proxy-->>Bridge: Blocked response
        else Policy requires approval
            Proxy->>TTY: Ask operator on host terminal
            TTY-->>Proxy: Exact scoped grant or denial
            Proxy->>Policy: Revalidate decision before connect
        else Policy allows
            Policy-->>Proxy: ALLOW
        end
        opt Destination is allowed
            Proxy->>Proxy: Resolve and reject non-global/private addresses
            Proxy->>Audit: Record decision and connection outcome
        end
    end

    Agent-->>Bwrap: Exit status
    Bwrap-->>CLI: Child result and sandbox-start status
    CLI->>Stage: Final manifest and workspace diff
    CLI->>Audit: Finalize summary and report
    Audit-->>Dev: Paths to audit, diff, summary and report
~~~

### 4.4 Data flow details

1. **Input:** the user provides a workspace directory, a YAML policy, runtime limits and a command after --.
2. **Validation:** the loader uses a safe YAML loader and strict Pydantic models. Unsupported fields, duplicate mapping keys and invalid schema values must fail closed.
3. **Staging:** the original project is copied to a session workspace. The session output directory is separate from the original project and includes manifests/diff evidence.
4. **Preflight:** the supervisor verifies that the host is Linux, Bubblewrap is trusted and sufficiently recent, and the required namespace/sandbox configuration works. A setup failure must not silently fall back to unsandboxed execution.
5. **Execution:** Bubblewrap starts the command with the configured namespaces, mounts, seccomp filter, environment restrictions and resource limits.
6. **Network:** the agent’s proxy-aware HTTP/HTTPS request reaches the guest bridge, travels over the UNIX socket to the host proxy, and is evaluated before an upstream connection is attempted.
7. **Approval:** supported approval requests are shown on the host terminal rather than the agent’s stdin. A grant is limited to a particular action, target and rule and is revalidated before use.
8. **Evidence:** the supervisor records events and finalizes the hash-chained audit log, workspace diff, session summary and report.
9. **Review:** the operator verifies the audit and inspects staged changes. Export creates a separate review copy; discard removes the staged workspace copy while preserving evidence.

### 4.5 Communication architecture style

This is a **local modular application with multiple process and trust boundaries**, not a microservices or distributed-systems architecture.

| Communication path | Style | Why it is used |
|---|---|---|
| User → CLI | Terminal arguments, stdout/stderr and host terminal | Local operator workflow |
| CLI → policy, audit, workspace modules | In-process Python function calls | Simple modular control plane |
| Supervisor → sandbox | OS process creation with a Bubblewrap argument vector | Establish an OS boundary around the child command |
| Agent → guest bridge | TCP listener on sandbox loopback using HTTP proxy / HTTPS CONNECT semantics | Agent tools commonly support HTTP proxy variables |
| Guest bridge → host proxy | UNIX domain socket mounted into the sandbox | IPC channel across network namespace isolation |
| Proxy → external destination | Host-side TCP connection to a checked address | Keep external network access behind policy decisions |
| Approval broker → operator | Dedicated host /dev/tty interaction | Prevent the agent from approving its own action via controlled stdin |
| Supervisor → artifacts | Local JSON, JSONL and Markdown files | Portable, inspectable evidence without a database |
| CI → test suite | GitHub Actions jobs on Linux runners | Reproducible regression and packaging checks |

There is no public REST API, message queue, remote scheduler or persistent database in the current design. The HTTP protocol is used by the proxy-facing agent client; it is not a web API for the entire application.

## 5. Requirements

### 5.1 Functional requirements

| ID | Requirement | Implementation / verification |
|---|---|---|
| FR-01 | Validate policy files against a versioned schema | validate-policy, schema/parser tests |
| FR-02 | Reject unknown schema fields, invalid versions, duplicate YAML keys and duplicate rule IDs | Strict parser and Pydantic models |
| FR-03 | Evaluate supported filesystem, command and network actions deterministically | evaluate, policy engine tests |
| FR-04 | Apply deny > require-approval > allow > default-deny precedence | Policy unit and regression tests |
| FR-05 | Simulate mock attack scenarios without claiming OS enforcement | simulate banner and artifact assertions |
| FR-06 | Start a command only after sandbox preflight succeeds | run, Bubblewrap enforcement tests |
| FR-07 | Stage project contents in a separate workspace copy | Workspace snapshot/staging tests |
| FR-08 | Isolate process/filesystem/network visibility with Linux sandbox mechanisms | Real Bubblewrap CI tests, where kernel capabilities permit |
| FR-09 | Mediate proxy-routed HTTP requests and HTTPS CONNECT destinations | Host proxy, guest bridge and network tests |
| FR-10 | Ask for host approval on supported require-approval paths and fail closed on refusal, expiry or mismatch | Approval broker and proxy/gate tests |
| FR-11 | Write verifiable audit evidence and a session report | Audit logger/verifier and report tests |
| FR-12 | Review/export/discard staged changes without automatically overwriting the original project | Recovery workflow tests |

### 5.2 Non-functional requirements

- **Fail closed:** malformed policy, proxy request, approval or sandbox setup must not default to an unverified allow.
- **Least privilege:** do not expose unrelated host directories and credentials to the child process unnecessarily.
- **Determinism:** the same policy and action request should yield the same policy decision.
- **Auditability:** record decisions and outcomes while separating observed events from activity the system cannot observe.
- **Reviewability:** session files should be inspectable with ordinary local tools.
- **Maintainability:** use explicit modules and typed models rather than one large CLI script.
- **Testability:** deterministic unit tests plus real Linux enforcement tests and adversarial fixtures.
- **Portability of the control plane:** Python packaging supports Python 3.11+; actual enforcement is Linux-specific and host-configuration-dependent.
- **Evidence-based claims:** test counts, coverage and runtime results are reported only when measured by CI; passing tests are not presented as a security proof.

### 5.3 Constraints

- Linux is required for real Bubblewrap enforcement.
- The configured host must support unprivileged user namespaces and the required Bubblewrap operations; distro security policies such as AppArmor may affect this.
- The project currently targets Bubblewrap 0.12.0 or newer in its preflight/CI approach.
- Network mediation depends on the guest bridge and proxy-aware clients using the provided proxy configuration.
- HTTPS CONNECT traffic remains encrypted end-to-end between the agent client and remote destination.
- Resource limits are per-process rlimit controls plus a supervisor timeout, not a full cgroup-wide aggregate quota.
- Session workspace staging and file export consume local disk space.

### 5.4 Assumptions

- The host OS and kernel are trusted.
- The developer is authorized to run the agent and choose the policy.
- A developer can inspect the policy and session results.
- A coding agent and files inside its workspace are not inherently trusted.
- The external destinations in a policy are intentionally allowed for that workflow.
- The source project is valuable enough that it should remain untouched until reviewed changes are copied back manually.

### 5.5 Non-goals

- Proving an agent’s reasoning is safe.
- Preventing every possible side effect caused by a remote API call to an explicitly allowed destination.
- Inspecting TLS payloads, prompts or response bodies.
- Guaranteeing complete command-policy mediation for every child process.
- Replacing Linux kernel security, host endpoint protection, backups, source control or code review.
- Automatically merging agent output or restoring arbitrary external service state.
- Claiming protection against a fully privileged host attacker who can replace the executable, session directory and all audit evidence.

## 6. Technologies, languages and tools

| Technology / tool | Role in this project | Why it fits |
|---|---|---|
| **Python 3.11+** | CLI, policy engine, sandbox orchestration, proxy, audit and reports | Standard-library support for process, socket, filesystem and hashing tasks; quick iteration with types and tests |
| **Typer** | User-facing CLI and argument validation | Declarative subcommands and readable help output |
| **Rich** | Terminal tables, policy outcomes and session summaries | Makes operator decisions and failures easier to review |
| **Pydantic v2** | Strict versioned policy and model validation | Rejects unknown fields and invalid types before execution |
| **PyYAML SafeLoader (customized)** | Parse policy configuration | Safe parsing plus explicit duplicate-key rejection |
| **Bubblewrap (bwrap)** | Create a sandboxed mount/process/namespace view | User-space construction of Linux isolation using kernel primitives |
| **Linux namespaces** | Separate mount, PID, network, IPC and UTS views | Reduce access to host resources and ordinary network routing |
| **Seccomp-BPF** | Deny selected risky syscalls | Additional restriction layer alongside namespaces and mounts |
| **resource / rlimit** | Per-process CPU, memory, file-size and descriptor limits | Bound selected resource use without a cloud control plane |
| **UNIX domain sockets** | Host/guest bridge communication | IPC channel across the isolated network namespace |
| **HTTP proxy / HTTPS CONNECT** | Route outbound web requests through the policy decision point | Host and port can be checked before a connection is opened |
| **hashlib / hmac** | Audit hash chain and optional HMAC | Standard cryptographic primitives for tamper evidence |
| **pytest / pytest-cov** | Unit, integration and coverage reporting | Reproducible test runner with measurable code coverage |
| **Hypothesis** | Generate malformed/edge-case input for bounded property tests | Explore input classes beyond hand-picked examples |
| **Ruff** | Lint checks | Quick static checks for common Python errors |
| **mypy (strict)** | Static type checking | Catch interface and type inconsistencies in the Python package |
| **build / twine** | Build and validate distribution files | Check wheel/sdist packaging and metadata |
| **GitHub Actions** | Linux runtime matrix and quality gates | Repeatable tests on Ubuntu/Python combinations |

There is no frontend framework because the project is a terminal tool, not a web application. There is no SQL database because the session model is local files and in-memory policy evaluation.

## 7. What a student should know before building this

This project is advanced. You can still learn through it, but attempting the full sandbox before understanding the control plane makes debugging unnecessarily difficult.

### 7.1 Core skills required

- Python functions, classes, modules, type hints, exceptions and package structure.
- CLI arguments and subprocess execution, including exit codes and signals.
- Filesystem operations: paths, permissions, symlinks, copying files and handling errors.
- JSON/YAML parsing and schema validation.
- Unit testing, fixtures, temporary directories and integration tests.
- Basic Linux terminal usage, environment variables, processes and permissions.
- Basic networking: IP addresses, ports, TCP, DNS, HTTP requests and HTTPS.

**A useful self-check:** you should be able to write a Python CLI that reads a YAML file, validates its fields, evaluates a rule against an input, writes a JSONL file and tests each behavior.

### 7.2 Supporting skills

- Git branching, commits, diffs and clean working-tree habits.
- Virtual environments, pip, pyproject.toml and editable installation.
- Python logging, deterministic serialization and hashing.
- HTTP headers, proxy variables and HTTPS CONNECT semantics.
- Linux mount and PID concepts, user namespaces and process isolation.
- Threat modeling: assets, entry points, trust boundaries, attacker capabilities and residual risk.
- GitHub Actions and reading CI logs.
- Secure configuration practices and keeping credentials out of logs.

### 7.3 Advanced skills

- Bubblewrap argument construction and mount namespace semantics.
- Seccomp-BPF limitations and syscall behavior across architectures/kernels.
- DNS rebinding, private-address checks, IPv4-mapped IPv6 and connection pinning.
- TOCTOU races, symlink attacks, file descriptors and target fingerprinting.
- Audit-chain anchoring, HMAC key custody and tamper-evidence limits.
- Property-based testing and adversarial corpus design.
- Resource isolation via cgroups versus per-process rlimit.
- Reviewing security properties of third-party sandbox software and upstream releases.

You do not need to master every advanced topic before starting. The roadmap below deliberately begins with policy validation and simulation, then introduces OS enforcement and network mediation.

## 8. Step-by-step build roadmap

This view describes **how to build the system in a learning-friendly order**. It is separate from the phase overview and lifecycle view later in the README. Steps can overlap during real development; each step still has a concrete deliverable and verification gate.

### Step 0 — Define the problem and trust boundaries

- **Objective:** Decide which resources must be protected and which attacker behaviors the MVP must handle.
- **What to build:** Problem statement, protected-asset inventory, threat scenarios, trust-boundary diagram, non-goals and acceptance criteria.
- **Inputs:** Coding-agent workflow, developer requirements, Linux sandbox capabilities and expected usage constraints.
- **Technologies:** Markdown, Mermaid diagrams, Git.
- **Tools:** GitHub, threat-model worksheets, review checklist.
- **Expected output:** A threat model with explicit promises and explicit limitations.
- **Verification:** Every claimed security property has a proposed enforcement point and a test idea; simulation is distinguished from real enforcement.
- **Common problems:** Treating instructions to the model as a firewall; confusing policy decisions with kernel enforcement; ignoring allowed-API exfiltration.
- **Next step:** Convert the desired controls into strict policy objects and validation rules.

### Step 1 — Implement the versioned policy schema and parser

- **Objective:** Reject unsafe or ambiguous configuration before a session starts.
- **What to build:** PolicyDocument, filesystem/command/network rule models, safe YAML loading, duplicate-key rejection and unique rule IDs.
- **Inputs:** Policy examples, schema version, allowed fields, default-deny requirement.
- **Technologies:** Python, Pydantic v2, PyYAML.
- **Tools:** Editor, pytest, Ruff, mypy.
- **Expected output:** policies/strict-default.yaml and a parser that returns either a validated model or an explicit policy error.
- **Verification:** Test unknown fields, unsupported schema versions, malformed YAML, duplicate keys/IDs, invalid ports and invalid field types.
- **Common problems:** PyYAML normally overwrites duplicate keys unless customized; silently accepting misspelled fields can change policy intent.
- **Next step:** Evaluate actions deterministically using the validated model.

### Step 2 — Build the deterministic policy engine and CLI evaluation

- **Objective:** Make an action decision predictable and independently testable.
- **What to build:** ActionRequest, EvaluationResult, path normalization, filesystem/command/network matchers, rule precedence and evaluate.
- **Inputs:** Validated policy, action category, operation, target and optional workspace context.
- **Technologies:** Python, Pydantic models, Typer.
- **Tools:** pytest, CLI runner, temporary fixtures.
- **Expected output:** agent-boundary evaluate shows a policy-only outcome and a matched rule or default-deny reason.
- **Verification:** Deny overrides approval and allow; unmatched operations deny; path traversal is not treated as an in-workspace path.
- **Common problems:** Incorrect glob semantics, normalized path confusion, and assuming a policy result itself blocks a real process.
- **Next step:** Add a simulation workflow that exercises realistic actions without executing them on the host.

### Step 3 — Add simulation, structured audit events and reports

- **Objective:** Show how rules respond and produce reviewable evidence without requiring a real agent.
- **What to build:** Mock-agent scenarios, JSONL event writer, canonical event serialization, hash chaining, optional HMAC, audit verifier and Markdown/terminal reporting.
- **Inputs:** Policy decisions, scenario steps and event payloads.
- **Technologies:** json, hashlib, hmac, Typer/Rich, pytest.
- **Tools:** pytest, text diff, agent-boundary verify-audit.
- **Expected output:** Clearly labelled simulation output plus audit and report files.
- **Verification:** Mutate/delete/reorder records and check verification fails; confirm simulation output says no OS enforcement occurred.
- **Common problems:** Calling a simulated deny “blocked by the kernel”; assuming a hash chain protects against replacement of the entire log bundle.
- **Next step:** Establish preflight and process limits before invoking untrusted code.

### Step 4 — Build Bubblewrap preflight and resource-limit validation

- **Objective:** Refuse to launch the target command unless the required Linux sandbox is available.
- **What to build:** Trusted-binary checks, version parsing, a harmless preflight probe, ResourceLimits validation, deterministic errors and exit behavior.
- **Inputs:** Linux host, Bubblewrap binary, requested timeout/CPU/memory/file-size/file-descriptor limits.
- **Technologies:** Bubblewrap, Python subprocess, resource, pytest.
- **Tools:** Linux terminal, bwrap --version, namespace probe, GitHub Actions.
- **Expected output:** A preflight result that allows sandbox construction or fails closed before the target command starts.
- **Verification:** Missing/old/untrusted bwrap, invalid limits and unavailable namespaces are rejected; assert the requested command is not started after failure.
- **Common problems:** Ubuntu AppArmor or kernel configuration prevents unprivileged namespaces; a laptop/container CI runner may have different capabilities.
- **Next step:** Stage the workspace and specify its filesystem visibility.

### Step 5 — Stage the workspace and build filesystem restrictions

- **Objective:** Keep agent edits separate from the original project and protect sensitive content.
- **What to build:** Private session directory, staged workspace copy, baseline manifest, secret-like path exclusion/masking, protected Git metadata, final manifest and diff.
- **Inputs:** Source workspace, filesystem rules, session output root.
- **Technologies:** Python pathlib, filesystem metadata, SHA-256 fingerprints, Bubblewrap mount arguments.
- **Tools:** pytest temporary directories, symlink fixtures, Git diff, filesystem inspection.
- **Expected output:** A private workspace plus baseline/final manifests and an added/modified/deleted file summary.
- **Verification:** Original source is unchanged; protected paths are absent/masked as intended; symlinks and path traversal cannot be used by guarded file tools to cross the workspace boundary.
- **Common problems:** File races, special files, hidden Git hooks, directory permissions and assuming a filename glob alone is a kernel-enforced policy.
- **Next step:** Run the staged command inside the namespace configuration.

### Step 6 — Enforce OS sandboxing and process restrictions

- **Objective:** Use kernel-enforced boundaries to isolate the agent process.
- **What to build:** Bubblewrap argv construction, mount tree, user/PID/network/IPC/UTS namespaces, Seccomp-BPF denylist, environment sanitization, per-process rlimit controls and wall-clock timeout.
- **Inputs:** Valid preflight, staged workspace, user command and validated resource limits.
- **Technologies:** Bubblewrap, Linux namespaces, Seccomp-BPF, Python subprocess/resource modules.
- **Tools:** Linux CI, process inspection only in a safe test environment, pytest enforcement fixtures.
- **Expected output:** A sandboxed child command and a truthful sandbox-started outcome.
- **Verification:** Test that the staged command cannot access unmounted host paths or open ordinary direct network sockets; verify setup failure does not fall back to unsandboxed execution.
- **Common problems:** Namespace and seccomp ABI differences, architecture-specific syscall numbering, mount ordering, permissions and CI sandbox restrictions.
- **Next step:** Build the supported, narrow network communication path.

### Step 7 — Add the guest bridge and host policy proxy

- **Objective:** Allow only proxy-routed HTTP/HTTPS requests evaluated by the host policy.
- **What to build:** Guest loopback listener, mounted UNIX socket, host proxy parser, destination policy evaluation, DNS resolution, public-address validation, pinned-address connect, relay and audit events.
- **Inputs:** Network rules, HTTP request/CONNECT headers and resolver results.
- **Technologies:** Python sockets, socketserver, UNIX domain sockets, HTTP proxy semantics, ipaddress.
- **Tools:** Mock resolver/connector tests, local sockets, adversarial test fixtures.
- **Expected output:** A proxy path that denies unmatched/unsafe targets and opens allowed connections only through the host proxy.
- **Verification:** Duplicate/malformed headers and ambiguous framing fail before upstream connect; mixed public/private DNS answers, loopback and private IP results are denied; audit log integrity verifies.
- **Common problems:** HTTP parser differences, DNS rebinding, proxy-unaware clients, TLS payload visibility assumptions, and leaked host proxy socket permissions.
- **Next step:** Add explicit approvals for supported operations and mediate guarded file actions.

### Step 8 — Add scoped approvals and guarded-action adapters

- **Objective:** Add a human decision point for operations explicitly routed through an approval-capable adapter.
- **What to build:** Host /dev/tty broker, exact action/target/rule grants, expiration and one-use consumption, revocation, target-state fingerprinting, GuardedActionGate and guarded workspace helpers.
- **Inputs:** A policy result of require-approval, exact action target and host-terminal response.
- **Technologies:** Python, os, hashlib, threading, policy engine and audit logger.
- **Tools:** pytest, fake TTY readers, state-change/race fixtures.
- **Expected output:** An explicit allow/deny result plus audit records for requested, granted, denied, expired, revoked or consumed approval.
- **Verification:** Refusal, missing broker, expiry, reuse, wrong target/rule and target replacement while prompting must not authorize the operation.
- **Common problems:** Assuming the kernel pauses arbitrary open/unlink calls for interactive approval; incorrectly implying that all shell commands route through the gate.
- **Next step:** Make results safely reviewable and exports explicit.

### Step 9 — Build review, export and staged-copy cleanup workflows

- **Objective:** Let the operator inspect results without automatic write-back to the original source.
- **What to build:** review-session, export-reviewed-changes and discard-workspace-copy.
- **Inputs:** Session summary, diff manifest and staged workspace.
- **Technologies:** Python filesystem APIs, JSON, Rich tables and defensive path validation.
- **Tools:** pytest, path-traversal and symlink fixtures, temporary output directories.
- **Expected output:** A reviewable list of changed paths, a separate export directory, or a discarded staged copy while preserving audit evidence.
- **Verification:** Export rejects traversal, symlinks and overwrite; discard requires explicit confirmation and retains logs/manifests/report.
- **Common problems:** Treating export as a safe merge; trusting a malicious or corrupted diff manifest; confusing staged copy deletion with original workspace deletion.
- **Next step:** Validate adversarial behavior across supported Linux and Python environments.

### Step 10 — Adversarial verification, packaging and release checklist

- **Objective:** Re-run the system’s accepted behaviors in clean, repeatable environments and document what is not verified.
- **What to build:** Regression tests, bounded Hypothesis property tests, CI matrix, Ruff/mypy gates, CLI smoke checks, wheel/sdist build/install checks, security evaluation and release checklist.
- **Inputs:** Threat scenarios, test fixtures, source tree and supported environment matrix.
- **Technologies:** pytest, Hypothesis, pytest-cov, Ruff, mypy, build, twine and GitHub Actions.
- **Tools:** Linux runners, GitHub Actions logs, package artifacts.
- **Expected output:** A reproducible CI run linked to an exact commit and a document of residual risks.
- **Verification:** All defined automated jobs on the current commit pass; skipped enforcement tests are inspected and are never presented as a successful enforcement result.
- **Common problems:** Platform-specific test behavior, version drift, false confidence from a passing happy path, and unmeasured performance claims.
- **Next step:** Obtain independent review, broaden platform/fuzz coverage and only then consider a production-oriented release process.

## 9. Stage-wise software development lifecycle

The previous section is a linear learning roadmap. Real software development is iterative, so this table explains the lifecycle activities that can overlap across steps.

| Lifecycle stage | Questions and activities | Deliverables | How the stage is verified |
|---|---|---|---|
| **1. Problem definition** | Which agent actions are risky? What is trusted? What is in scope? | Problem statement, assets, attacker model, non-goals | Review each threat against a real control or explicitly named residual risk |
| **2. Requirements** | What must be allowed, denied, approved, logged or rejected? Which failures must fail closed? | Functional/non-functional requirements, constraints, acceptance criteria | Map requirements to test names, code modules and evidence |
| **3. Architecture development** | Where is the enforcement boundary? Which processes communicate? What runs inside or outside the sandbox? | Mermaid architecture/data-flow diagrams, interfaces and module boundaries | Review trust boundaries, authority and failure modes before integration |
| **4. Implementation** | Can each module be built and tested separately? | Parser, engine, logger, sandbox runner, proxy, approval and recovery code | Unit tests, linting, type checks and code review |
| **5. Integration** | Do the CLI, policy engine, Bubblewrap runner, guest bridge and host proxy work together? | Runnable local session and documented CLI flows | Integration tests and real Linux enforcement tests |
| **6. Testing and adversarial evaluation** | Do malformed inputs, denial paths, target races and sandbox failures remain safe? | Unit/integration/adversarial/property tests, coverage output | Current-commit CI results on supported matrix entries; inspect skips and logs |
| **7. Deployment** | What must be installed on a developer host? What conditions block startup? | Package, installation instructions, environment requirements | Clean virtual-environment install and preflight tests |
| **8. Observability** | What can the supervisor truthfully observe? What is outside its visibility? | Audit events, manifests, diff, session summary and report | Verify record chain, compare before/after workspace and label blind spots |
| **9. Verification** | Does the implementation actually enforce its documented claims? | Evidence table, reproducible CI run, residual-risk register | Compare each README claim to code/tests; do not count a mock as enforcement |
| **10. Documentation** | Can a new student install, run, inspect, test and explain the project? | README, policy example, lifecycle/roadmap, security evaluation and release checklist | Follow the setup and demo steps from a clean checkout |
| **11. Maintenance and iteration** | How do new kernel/Python versions, regressions or policy changes affect security? | Versioned changes, dependency updates, test fixtures and updated limitations | Re-run all checks for the new commit and review the changed enforcement surface |

The stages are not gates that happen only once. For example, a new proxy test can reveal a requirement ambiguity, forcing architecture and implementation changes before the lifecycle is complete.

## 10. Data design

The project is file-backed and local. It has no SQL/NoSQL database and no remote event pipeline in the current MVP.

### 10.1 Data sources

| Source | Example | Used for |
|---|---|---|
| User input | CLI arguments, command after --, selected workspace and limits | Session setup |
| Policy file | policies/strict-default.yaml | Policy decisions and protected-path/network rules |
| Workspace filesystem | File paths, metadata, content hashes, symlink information | Staging, manifests and diff |
| Agent process | Exit status, process outcome and proxy traffic | Session outcome and observed activity |
| Proxy request | Method, host, port, headers, CONNECT authority | Network decision and destination metadata |
| Human operator | Exact approval phrase from host terminal | Scoped approval grant or denial |
| Host environment | OS, Bubblewrap version, user namespace capability | Preflight and fail-closed startup |
| Test fixtures | Mock attack scenario, malformed HTTP/YAML, fake resolver outcomes | Reproducible testing without calling a real LLM |

### 10.2 Core models and example entities

| Entity | Important fields (conceptual) | Purpose |
|---|---|---|
| PolicyDocument | schema_version, policy_id, workspace_root, default_decision, filesystem, commands, network | Validated rules for a run |
| Filesystem rule | id, operations, paths, reason | Define path/operation decisions |
| Command rule | id, executables, optional arg_patterns, reason | Describe supported command policy matching |
| Network rule | id, hosts, ports, reason | Match destination host and port |
| ActionRequest | category, operation, target, optional action identifier/actor/symlink context | Represent an action being evaluated by the policy engine |
| EvaluationResult | decision, matched rule, normalized target, reason and boundary information | Explain why the engine returned a result |
| ApprovalGrant | grant identifier, action, target, rule ID, expiration | Hold one-use approval state in the supervisor process |
| Audit event/record | sequence, time, event type, payload, previous hash, event hash, optional HMAC | Evidence of recorded session events |
| Session manifest | paths and relevant filesystem metadata/fingerprints | Record baseline/final staged workspace state |
| Session diff | added, modified and deleted paths with relevant metadata | Show changes made to the staged copy |
| Session report | session metadata, sandbox outcome, decisions, artifact references and limitations | Human-readable review summary |

The table describes the shape and purpose of the models; it is not a promise that every field shown is serialized into every record. Refer to the code for the exact schema.

### 10.3 Persistence, indexes and caching

- **Persistence:** local policy YAML, audit JSONL, manifests/diff/session JSON and Markdown report files.
- **Database indexes:** none. There is no database.
- **Policy lookup:** the current in-process policy engine evaluates configured rule lists; it is not a large indexed policy database.
- **Approval state:** active grants are maintained in supervisor memory and expire/are consumed/revoked; this is not a durable approval database.
- **Cache:** there is no dedicated persistent application cache. A request’s resolved addresses are used for that connection attempt; the application does not maintain a cross-session DNS result store.
- **Retention:** session files remain in the local output directory until the user manages them. A production deployment would need a deliberate retention and cleanup policy.
- **Data minimization:** audit records are primarily decision and outcome metadata. The proxy does not decrypt HTTPS, but callers should still avoid sending secrets in destinations, paths or other fields that could become metadata.

### 10.4 Audit integrity model

The audit writer creates canonical event serialization and links records through a SHA-256 hash chain. Optional HMAC signing can add verification when key material is managed separately. The verifier checks continuity and can accept an expected final head hash.

This improves tamper evidence; it does not create immutable storage. If a person can replace the whole audit bundle and there is no independently stored final anchor or protected HMAC key, they may be able to recompute the chain.

## 11. API and interface design

### 11.1 User-facing CLI

The CLI is the primary user interface. It is not a REST service.

| Command | Purpose | Executes an untrusted command? |
|---|---|---|
| agent-boundary --help | Show CLI help | No |
| agent-boundary --version | Print package version | No |
| agent-boundary validate-policy policy.yaml | Strictly validate policy schema/rules | No |
| agent-boundary evaluate --policy ... --category ... --operation ... --target ... | Evaluate one action against policy | **No — policy evaluation only** |
| agent-boundary simulate --policy ... --scenario ... --output-dir ... | Run a mock scenario and generate evidence | **No OS enforcement** |
| agent-boundary run --workspace ... --policy ... -- command args... | Stage a workspace and run the supplied command under the Linux sandbox | Yes, after successful preflight |
| agent-boundary verify-audit audit.jsonl | Verify audit continuity; optional expected head hash/HMAC requirements | No |
| agent-boundary report session-dir | Generate or print a human-readable session report | No |
| agent-boundary review-session session-dir | Review staged changed paths and session metadata | No |
| agent-boundary export-reviewed-changes session-dir destination | Copy added/modified regular files to a separate review directory without overwriting existing files | File copy to review destination only |
| agent-boundary discard-workspace-copy session-dir --yes | Explicitly delete only that session's staged copy while retaining evidence | Deletes staged copy after confirmation |

Use the CLI help for each command to inspect the installed version’s exact options.

### 11.2 Example policy evaluation

This evaluates a request against the policy engine; it does not attempt to read the file from disk:

~~~bash
agent-boundary evaluate \
  --policy policies/strict-default.yaml \
  --category filesystem \
  --operation read \
  --target /workspace/.env
~~~

The expected policy outcome is DENY under the default secret rule. Treat the CLI’s policy banner as a reminder that this is a decision, not proof that a kernel denied a syscall.

### 11.3 Example mock simulation

Use an output directory that does not already contain a previous session:

~~~bash
SIM_PARENT="$(mktemp -d)"
agent-boundary simulate \
  --policy policies/strict-default.yaml \
  --scenario scenarios/mock-agent-attack-suite.json \
  --output-dir "$SIM_PARENT/simulation"
~~~

Simulation is useful for learning rule precedence, inspecting decisions and checking the audit format without spending LLM API quota or running an untrusted command. It deliberately prints a **SIMULATION MODE — NO OS ENFORCEMENT** banner.

### 11.4 Example sandbox execution

Run a harmless command first:

~~~bash
agent-boundary run \
  --workspace ./my-project \
  --policy policies/strict-default.yaml \
  --timeout 600 \
  --cpu-seconds 600 \
  --memory-mib 4096 \
  --file-size-mib 512 \
  --open-files 1024 \
  -- /bin/sh -c 'pwd; ls -la'
~~~

The child operates on a private staged copy. It does not automatically modify the original my-project directory. Session artifacts default to ~/.local/state/agent-boundary/runs/; --output-root can select a separate parent directory outside the source workspace.

### 11.5 Internal Python APIs

Important in-process interfaces include:

- **PolicyEngine.evaluate(request)** — deterministic decision making.
- **run_sandboxed(...)** and Bubblewrap helper functions — preflight, argument construction and process lifecycle.
- **PolicyEnforcingProxy** — parses/mediates HTTP and HTTPS CONNECT destinations through the policy engine.
- **ApprovalBroker** — host-terminal approval request, grant consumption, expiration and revocation.
- **GuardedActionGate** — evaluates actions explicitly routed through an adapter and can run a mediated callback only after authorization.
- **GuardedWorkspaceTools** — policy-gated helper operations over regular files in a staged workspace.
- **AuditLogger / verify_audit_log(...)** — write and verify session evidence.

These are internal Python interfaces, not a stable public SDK commitment. Inspect docstrings and model definitions before creating a new adapter.

### 11.6 API and policy rules

- A policy file must use the supported schema version and reject unknown fields.
- Unknown or unmatched actions should default to deny.
- An explicit deny takes precedence over approval/allow; approval takes precedence over allow.
- Never translate “policy engine returned allow” into “kernel enforcement succeeded” without evidence from the execution path.
- A require-approval result is interactive only when the action is routed through an approval-capable broker/adapter. Do not assume every shell command is mediated.
- Proxy parsing must reject malformed or ambiguous request framing before connecting to an upstream destination.
- Audit events must distinguish policy decision, enforced outcome, approval activity and observed connection failure.
- The host-side proxy must reject non-global/private/loopback/link-local destinations even when a hostname rule appears to match.

### 11.7 User flows

**Flow A — Author or change a policy:** edit YAML → validate-policy → use evaluate on allow/deny/approval cases → add tests → commit the policy and tests together.

**Flow B — Demonstrate expected behavior:** run simulate → inspect decision table → verify audit.jsonl → read session report. Do not claim this demonstrates OS enforcement.

**Flow C — Run a real isolated command:** validate policy → confirm Bubblewrap preflight → run a benign command → locate session directory → inspect report/diff → verify audit → export only reviewed files or discard the staged copy.

**Flow D — Add a new guarded tool:** define action schema and target representation → evaluate policy → route the operation through GuardedActionGate → supply target-state fingerprints for mutable resources → test denial, approval, timeout, target changes and audit results. Keep kernel restrictions in place for everything that bypasses that adapter.

### 11.8 Testing strategy

- **Unit:** policy schema, rule precedence, normalization, audit hash/HMAC verification, approval grant lifecycle and path helpers.
- **Integration:** CLI commands, proxy/bridge behavior, workspace staging/diff, report generation and packaging.
- **Adversarial:** malformed HTTP request lines/headers, ambiguous request framing, unusual host/port values, path traversal, symlinks, target mutation while approval is pending, bad DNS answers and tampered audit records.
- **Property-based:** bounded Hypothesis tests vary authority strings, headers, paths, policy fields and port values.
- **OS enforcement:** real Bubblewrap tests for mount/network/resource/startup behaviors on supported CI runners.
- **Regression:** retain each discovered bug as a targeted test.
- **Release gate:** use current-commit GitHub Actions results, not an earlier run, and check whether enforcement tests passed or were skipped.

## 12. Implementation plan and verification

Implementation should be vertical: produce a small behavior that can run and be tested before adding the next layer.

| Milestone | Work product | Proof required before moving forward |
|---|---|---|
| A. Validated configuration | Schema/parser | Invalid and ambiguous policies fail closed |
| B. Policy decisions | Engine/CLI | Precedence and boundary cases are deterministic |
| C. Evidence | Logger/verifier/report | Corruption and sequence changes fail verification |
| D. Real isolation | Bubblewrap backend | Target command does not start after failed preflight; kernel enforcement tests pass |
| E. Live network path | Guest bridge/host proxy | Direct network is isolated, malformed requests do not connect, safe hosts are policy-checked |
| F. Approvals | Approval broker/guarded gate | Exact scope, expiration, single use, target revalidation and refusal paths are tested |
| G. Recovery | Review/export/discard | Export refuses traversal/symlinks/overwrite; discard retains evidence |
| H. Release validation | CI matrix, lint/type/package checks and security docs | All automated jobs are green on one commit; residual risks remain documented |

**Verification is an engineering deliverable.** If a test is skipped because a host does not allow Bubblewrap namespaces, record the skip rather than calling the control tested. If a claim cannot be tested at syscall level, label the limit in the README and use a narrower claim.

## 13. Deployment architecture, infrastructure and secrets

### 13.1 Deployment architecture

The current deployment is on a developer’s Linux workstation:

- A Python CLI runs as the host supervisor.
- Bubblewrap launches the requested agent/command as a child in a namespace-isolated environment.
- The staged workspace and session artifacts live on local disk.
- A host-side policy proxy and guest bridge handle proxy-routed HTTP/HTTPS traffic.
- Audit, manifests, diff and report files are local files.
- No cloud control plane, central database, message broker or hosted UI is required.

### 13.2 Infrastructure prerequisites

- Linux and a working shell.
- Python 3.11 or newer.
- Bubblewrap 0.12.0+ according to the current project checks and CI setup.
- Linux kernel/user-namespace configuration that permits the required sandbox.
- A policy YAML file and a workspace directory.
- Package build/test dependencies when developing or running tests.

The exact result depends on the local kernel, distribution and security profile. A successful GitHub-hosted runner does not guarantee a local host will pass preflight.

### 13.3 Secrets management

There is no dedicated central secrets manager in the MVP. The safest default is not to expose unnecessary credentials to the child process.

- Do not put raw secrets in YAML policies, scenario files, tests, screenshots, audit payloads or README examples.
- Do not assume host environment variables are automatically available inside the sandbox; the runner sanitizes the inherited environment.
- If an agent needs an API credential, provide only the narrow credential needed for the task using an explicitly reviewed method, with a limited scope and lifetime. Credential injection is a separate security design problem, not a guaranteed feature of this prototype.
- Understand that allowing a legitimate LLM API means a prompt may send workspace content to that API; host/port allowlisting cannot distinguish legitimate inference from malicious exfiltration over the same allowed channel.
- Never share actual audit keys, signing secrets or private keys in a public repository.

### 13.4 Rollback and recovery

The main safety choice is **stage first, review before copying back**.

1. Inspect diff.json, final manifest and session_report.md.
2. Run verify-audit and, where used, verify against a separately retained expected head hash or HMAC.
3. Export desired added/modified files to a separate review directory.
4. Inspect and test exported code before copying it manually into the original repository.
5. Preserve the session evidence for debugging/security review.
6. Use discard-workspace-copy --yes only after reviewing the session; it removes the staged workspace copy while retaining the other session artifacts.

This is not a general-purpose rollback transaction. External API side effects, remote pushes, external service changes and other effects outside the staged workspace cannot be rolled back by deleting the staged copy.

## 14. Observability and auditability

### What the project records

Depending on the event and path taken, session artifacts can include:

- Session start/end and whether the sandbox child started.
- Policy decision, matched rule identifier and reason.
- Proxy-routed destination host/port, policy/enforced decision, checked upstream addresses and connection failures.
- Approval requested/granted/denied/expired/revoked/consumed events.
- Baseline/final workspace manifests and added/modified/deleted path diff.
- Exit status, resource/session configuration and a human-readable report.
- Audit chain head hash and verification output.

### What it does not observe completely

- A raw socket attempt rejected by the network namespace before it reaches the proxy may not appear as a destination-specific proxy event.
- HTTPS payloads remain encrypted; the proxy knows the CONNECT destination but does not see the URL path/body or prompt contents inside TLS.
- Operations that bypass the Python guarded adapters are not automatically recorded as guarded-action decisions.
- A hash-chain log is not immutable against a host user who can replace the complete log bundle and recompute the chain without a protected external anchor.
- A child process may have runtime behavior or side effects that are not fully captured by the workspace diff.

**Observability is not the same as enforcement.** Reports should say what the supervisor observed, what Linux enforced, and what is unknown.

## 15. Security model

### Assets to protect

- Host credentials and private keys.
- Source files outside the intended workspace.
- Common in-workspace secrets such as .env, .pem and .key files.
- Git hooks/configuration and workflow files that may create persistence or CI-side effects.
- Local services, private addresses and cloud metadata endpoints.
- The developer’s unstaged or uncommitted source tree.
- Audit and session evidence.

### Attacker capabilities considered

- Prompt injection in repository text, issues or tool output.
- Malicious or accidental destructive shell/Git actions.
- Attempts to read sensitive paths or escape via symlinks/path traversal.
- Attempts to contact private/loopback/metadata destinations or unapproved internet hosts.
- Malformed/ambiguous proxy HTTP headers and authority forms.
- Attempts to misuse approvals, race a target while approval is pending, or tamper with audit records.
- Resource exhaustion within the limits that are implemented and tested.

### Security principles

- Default deny and explicit rule precedence.
- Narrow host mount visibility and separate staged workspace.
- Network namespace isolation plus a mediated proxy path.
- Human approval is exact, time-limited and one-use for supported gated actions.
- Fail closed if setup, policy validation or approval verification fails.
- Preserve evidence and present it for review rather than applying changes automatically.
- Document the residual risk even when automated tests pass.

## 16. Performance, scalability and results

### 16.1 Measured CI results

The most recent fully verified CI matrix recorded for the implementation before this README refresh ran **93 tests successfully in each of four configurations**:

| CI configuration | Result | Full test-step duration |
|---|---:|---:|
| Ubuntu 22.04 / Python 3.11 | 93 passed | 44.80 seconds |
| Ubuntu 24.04 / Python 3.11 | 93 passed | 43.29 seconds |
| Ubuntu 24.04 / Python 3.12 | 93 passed | 24.37 seconds |
| Ubuntu 24.04 / Python 3.13 | 93 passed | 42.59 seconds |
| Separate static/type/package job | Passed | See workflow logs |

These are **CI test durations, not a benchmark of agent execution or proxy throughput**. Runner load, dependency installation and test composition may affect the times. Consult the [successful workflow](https://github.com/worksomaganesh/ai-agent-firewall/actions/runs/38987741089) for job-level logs and exact commit.

### 16.2 Before-versus-after results

No controlled performance benchmark was captured before the project implementation, so there is no scientifically valid numeric performance percentage to report. The comparison below is about implemented capabilities and automated evidence, not a fabricated speed-up.

| Area | Before the implementation (baseline) | Current evidence | What is not yet measured |
|---|---|---|---|
| Policy decisions | No executable project baseline captured | Strict schema, deterministic engine and policy tests | Rules/second across large policies |
| OS isolation | No project-run sandbox baseline captured | Real Bubblewrap enforcement tests in Linux CI | Isolation overhead against equivalent unsandboxed workloads |
| Network path | No host-mediated network firewall baseline captured | Proxy allow/deny, approvals and adversarial parsing tests | Requests/second, p50/p95 latency and concurrent tunnel capacity |
| Workspace handling | No captured snapshot timing | Manifests/diffs and recovery workflow tests | Copy/hash time against repository size and file count |
| Audit integrity | No project audit verification baseline captured | Tamper, sequence and HMAC/hash-chain tests | Audit events/second and storage growth under long sessions |
| Engineering quality | No baseline test count before implementation captured | 93 tests in each of four CI configurations plus static/package gate | Overall mutation score, exhaustive branch coverage and real-world attack prevention rate |

### 16.3 Expected performance costs and bottlenecks

These are engineering expectations, not benchmark claims:

- Copying and hashing a large repository grows with file count and data size.
- Policy evaluation walks configured rule collections; it is designed for local policies, not millions of rules.
- The host proxy and bridge add work to proxy-mediated network connections.
- Audit writes and filesystem hashing add disk I/O.
- Bubblewrap startup and namespace creation add overhead per session.
- Per-process rlimit values do not provide an aggregate CPU/memory budget for a large process tree.

### 16.4 Scalability

The current project scales **vertically as a local developer tool**, not horizontally as a multi-tenant service. There is no server fleet, central policy database or remote audit ingestion. Potential future work includes measured proxy benchmarks, large-workspace profiling, cgroup-based resource control, structured session retention, safe parallel sessions and a stable adapter interface—but these should be introduced only with defined requirements and tests.

## 17. Failure modes and how they are handled

| Failure mode | Expected behavior | How to investigate |
|---|---|---|
| Invalid/ambiguous YAML policy | Reject before running the target command | validate-policy; inspect the schema error |
| Missing, old or untrusted Bubblewrap | Fail preflight; do not silently run the requested command unsandboxed | bwrap --version, ownership/mode, namespace configuration and CLI error |
| User namespaces blocked by kernel/AppArmor | Fail closed with setup error | Check host distribution/kernel/security profile; compare with CI matrix |
| Proxy socket/bridge startup failure | Sandbox setup should fail or the request should fail closed; no unsandboxed network fallback | Inspect session artifacts and proxy startup error |
| Malformed HTTP authority/header/body framing | Return a client error and do not open the upstream connection | Run Phase IV adversarial tests and inspect the network audit event |
| DNS lookup fails or resolves to non-global/private addresses | Deny; do not connect to an unchecked answer | Check network rules and proxy decision reason |
| Approval denied, expired or mismatched | Deny the gated action and record supported approval/audit activity | Check host terminal prompt and session audit events |
| Workspace target changes during guarded approval | Revoke/deny instead of executing against an unverified target | Review target-state and approval audit events |
| Child command exits nonzero or times out | Preserve the exit outcome and available session evidence | Inspect summary, report and diff |
| Audit verification fails | Treat evidence as suspect; do not treat it as verified | verify-audit, optionally provide separately retained head hash/HMAC key |
| Export destination exists for a changed file | Refuse overwrite | Choose a new review-export directory |
| Session review reveals harmful edits | Do not copy them back; keep evidence, then discard the staged copy if appropriate | Inspect diff and exported files in isolation |

Error handling and fail-closed intent are tested, but arbitrary host compromise, every race window and every kernel failure mode cannot be ruled out by this table.

## 18. Pain points during implementation and testing

### Pain points during implementation

**1. Interactive approval versus kernel enforcement.** The kernel does not pause arbitrary file syscalls to ask a human a question. The implementation therefore separates static mount-based restrictions from host approval flows for operations explicitly routed through user-space guarded adapters.

**2. Network namespaces versus LLM connectivity.** Removing the agent’s direct network interface also removes ordinary outbound access. The guest bridge and mounted UNIX socket create one narrow path to the host proxy, which applies network policy before connecting.

**3. DNS rebinding and private destinations.** Checking only a hostname is insufficient if it resolves to loopback/private addresses or changes between checking and connection. The proxy validates resolved addresses and connects to the selected checked address for that request.

**4. Filesystem path races.** A target can be replaced with a symlink while an approval prompt is open. Guarded tools reject symlinks/path traversal and fingerprint targets so some target changes are detected before the mediated operation. This is not a universal openat2/FUSE syscall broker.

**5. Audit tampering.** A hash chain can detect many edits but cannot alone stop a host user from replacing the entire file and rebuilding the chain. Optional HMAC and an independently retained head hash are important for stronger tamper evidence.

### Pain points during testing

**1. CI is not the same as every developer host.** Ubuntu’s AppArmor/user-namespace configuration and containerized runners can change whether Bubblewrap starts. The CI workflow deliberately builds Bubblewrap and enables the required capabilities on ephemeral runners; this does not guarantee a personal machine behaves identically.

**2. Security tests must assert outcomes, not only function calls.** Proxy tests use mock DNS/connectors to verify malformed requests never reach upstream connection logic; real Bubblewrap tests are needed to validate the OS boundary.

**3. Regression tests can be more valuable than generic assertions.** Discovered parser, path, approval and audit issues are retained as focused examples and bounded Hypothesis properties.

**4. The test suite is not a proof.** Passing known cases does not rule out unknown parser differences, kernel issues or integration paths that bypass the adapters. Longer fuzzing and independent review remain release requirements.

## 19. Repository structure

~~~text
ai-agent-firewall/
├── README.md
├── pyproject.toml
├── bundle_phase1.py                 # Original project-bundling helper
├── ai-agent-firewall-phase1.zip     # Original imported bundle artifact
├── policies/
│   └── strict-default.yaml          # Fail-closed example policy
├── scenarios/
│   └── mock-agent-attack-suite.json # Mock scenario; no real LLM API needed
├── docs/
│   ├── security-evaluation-phase4.md
│   └── release-checklist.md
├── .github/
│   └── workflows/
│       └── phase1-tests.yml         # Current security/adversarial CI workflow
├── src/
│   └── agent_boundary/
│       ├── __init__.py
│       ├── cli.py
│       ├── simulator.py
│       ├── exit_codes.py
│       ├── policy/
│       │   ├── __init__.py
│       │   ├── schema.py            # Strict versioned models
│       │   ├── parser.py            # Safe YAML and duplicate-key validation
│       │   └── engine.py            # Deterministic decisions and normalization
│       ├── audit/
│       │   ├── __init__.py
│       │   ├── events.py            # Audit event and record definitions
│       │   ├── logger.py            # JSONL chain writer
│       │   ├── verifier.py          # Hash/HMAC verification
│       │   └── report.py            # Session report generator
│       └── sandbox/
│           ├── __init__.py
│           ├── approval.py          # Host-terminal approval broker
│           ├── bwrap.py             # OS sandbox construction and lifecycle
│           ├── guard.py             # Guarded-action policy gate
│           ├── guest_bridge.py      # In-sandbox loopback-to-UNIX relay
│           ├── proxy.py             # Host-side policy proxy
│           ├── seccomp.py           # Seccomp-BPF filter
│           ├── snapshot.py          # File manifests/fingerprints
│           ├── workspace.py         # Staging and workspace diff
│           └── workspace_tools.py   # Explicitly mediated regular-file tools
└── tests/
    ├── test_approval.py
    ├── test_guarded_action_gate.py
    ├── test_guarded_workspace_tools.py
    ├── test_network_proxy.py
    ├── test_phase1_acceptance.py
    ├── test_phase1_regressions.py
    ├── test_phase2_sandbox.py
    ├── test_phase3_workflows.py
    ├── test_phase4_adversarial.py
    ├── test_phase4_policy_properties.py
    └── test_phase4_properties.py
~~~

The exact tree may change as the project evolves. Use the repository tree as the source of truth when navigating files.

## 20. Setup instructions

### 20.1 Clone the repository

~~~bash
git clone https://github.com/worksomaganesh/ai-agent-firewall.git
cd ai-agent-firewall
~~~

### 20.2 Create a Python environment

~~~bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
~~~

Use Python 3.11 or newer. The command installs the application in editable mode and the test/quality extras.

### 20.3 Check Linux sandbox requirements

~~~bash
uname -s
bwrap --version
~~~

Real enforcement requires Linux and Bubblewrap 0.12.0+ with the required namespace support. If bwrap is missing or too old, install a trusted supported package/build following the project's release notes and upstream security guidance. Do not work around a failed preflight by running an untrusted agent outside the sandbox.

### 20.4 Validate policy and inspect CLI options

~~~bash
agent-boundary --help
agent-boundary --version
agent-boundary validate-policy policies/strict-default.yaml
~~~

### 20.5 Run tests

~~~bash
python -m pytest --cov=agent_boundary --cov-report=term-missing
python -m ruff check --select E4,E7,E9,F src tests
python -m mypy --follow-imports=silent src/agent_boundary
~~~

The project’s GitHub Actions workflow builds Bubblewrap for its ephemeral Linux runners, runs the suite on the documented Ubuntu/Python matrix, and checks package builds/clean installs. Some developer hosts cannot run all sandbox tests; inspect skips rather than assuming every enforcement path was tested.

## 21. Demo order — how to present the project

A good demo shows the problem, the decision logic, the real boundary, the evidence and the limitations in that order. Start with harmless commands and never use valuable real credentials or a production repository for the demo.

1. **Explain the threat:** an agent can be instructed by malicious repository content to read a secret, delete work or send code to an unexpected destination.
2. **Show the policy:** open policies/strict-default.yaml and explain the default deny, secret-path rules, workflow-edit approvals and network allowlist.
3. **Validate the policy:** run the validate-policy command.
4. **Demonstrate rule evaluation:** evaluate a read of /workspace/.env and show the DENY decision. Explicitly say this is a policy-only check, not a filesystem syscall test.
5. **Run the mock attack scenario:** use simulate with scenarios/mock-agent-attack-suite.json; point out the no-OS-enforcement banner and inspect its audit/report files.
6. **Run a harmless real sandbox command:** use the run example above on a throwaway test project. Show the sandbox-started result and explain that the original source is not the working copy.
7. **Show the network boundary:** explain that the child’s direct networking is isolated and proxy-aware requests go through the guest bridge and host policy proxy. Do not use a malicious external endpoint in a public demo.
8. **Show evidence:** locate audit.jsonl, run verify-audit, inspect the report and compare baseline/final manifests or diff.json.
9. **Show review-first recovery:** inspect the session; optionally export changed test files into a new review directory; demonstrate that existing files are not overwritten.
10. **End with honest limitations:** TLS payloads remain opaque, not every child command passes through the guarded adapter, and the project is not independently audited or production-ready.

### Suggested demo narration

> “The project does not try to make a language model promise to behave. It stages the repository into a separate workspace, runs the child inside a Linux sandbox, blocks direct network access, and mediates supported HTTP/HTTPS proxy requests on the host. A deterministic policy decides whether a destination is allowed, denied or requires supported human approval. The session creates audit and workspace-change evidence. Those controls reduce specific risks, but the prototype does not observe every operation or decrypt TLS, so the report is careful about what was and was not verified.”

## 22. Lessons learned

- **Security claims need a boundary.** “The policy denied it” and “the kernel prevented it” are different statements.
- **A small MVP is safer than broad, unverified promises.** Explicitly document which operations use OS controls and which pass through a user-space adapter.
- **Fail closed at integration points.** Invalid YAML, malformed requests, missing namespaces or refused approvals must not silently widen permission.
- **The trust boundary should be visible in architecture.** The host supervisor, kernel sandbox, untrusted child, bridge and proxy have different responsibilities.
- **A proxy is not full data-loss prevention.** Host/port control cannot inspect encrypted traffic or stop exfiltration to a permitted LLM endpoint.
- **Approvals are difficult to secure.** They need exact scope, expiration, single-use grants and target revalidation—not merely a yes/no prompt.
- **Auditability requires external trust.** A local hash chain is useful evidence, but independent anchoring and key custody matter.
- **Adversarial tests discover assumptions.** Malformed headers, mixed DNS answers, symlink races and invalid schema values often reveal design weaknesses that happy-path tests miss.
- **CI evidence must be tied to a commit and environment.** Test counts from an old commit should not be reused as the current result.
- **Unmeasured metrics should remain unclaimed.** Passing tests and their duration are not equivalent to measured protection rate, throughput or performance overhead.

## 23. How this project can serve as portfolio proof

This project can demonstrate more than “I called an LLM API.” It provides evidence of engineering tradeoffs, secure systems design, tests and documentation. The strongest presentation is precise about what was built and what remains open.

### What to show a reviewer or recruiter

- **Problem framing:** the threat model and the specific assets/attack paths the prototype aims to control.
- **System architecture:** the Mermaid diagrams and the separation between CLI, trusted supervisor, Linux kernel boundary, agent process, proxy and audit artifacts.
- **Code quality:** strict models/parser, typed policy engine, modular sandbox/proxy/approval/audit components.
- **Tests:** adversarial and property-based inputs, real Bubblewrap tests, Linux/Python CI matrix, Ruff/mypy checks and clean package installation.
- **Evidence:** link to a successful workflow run, tests tied to exact commits, and the report/audit format.
- **Security judgement:** limitations that are explicitly disclosed, no fake benchmark data and no claim of perfect security.
- **Reproducibility:** clone/install/validate/simulate/run instructions that another student can follow.

### Portfolio description example

> **agent-boundary — AI Agent Firewall Prototype**  
> Built a Linux-first Python CLI for running AI coding commands in a Bubblewrap sandbox with deterministic YAML policy evaluation, a host-side HTTP/HTTPS policy proxy, scoped human approvals for supported mediated actions, hash-chained session audit logs and workspace-diff review. Added adversarial and property-based tests, Linux/Python CI coverage, static type/lint checks and clean wheel/sdist installation verification. Documented residual risks including opaque TLS, incomplete universal command mediation and the need for independent security review.

Use this description only while it accurately reflects the code and current CI results. Do not claim that the firewall prevents every prompt injection, secures every API call, or is production-certified.

## 24. Future improvements

Potential next iterations should each have a threat-model reason, acceptance criteria and test evidence:

1. Extend kernel/AppArmor/distribution validation beyond the current Ubuntu matrix.
2. Add longer-running fuzz campaigns and differential HTTP parser testing.
3. Add deeper policy-schema property tests and mutation-test the policy engine.
4. Harden filesystem race resistance with directory-file-descriptor-based APIs where appropriate.
5. Add cgroup-backed aggregate resource budgets for process trees.
6. Design an adapter interface for selected agent/tool protocols and document which operations are actually mediated.
7. Add independent audit anchoring and a clearly defined HMAC key-management workflow.
8. Benchmark startup, repository staging, proxy throughput/latency and audit overhead using repeatable workloads.
9. Add recovery tests for interrupted export, disk-full, cancellation and partial session finalization.
10. Commission an independent security review before making any production-oriented claim.

These are future work, not existing product features.

## 25. Project status and release policy

The project roadmap contains five phases: Phase 0 (architecture) and implementation Phases 1–4.

- **Phase 0:** architecture, threat model and acceptance scope.
- **Phase 1:** reliable core — policy, CLI, simulation and audit.
- **Phase 2:** OS isolation, workspace staging, resource controls and live proxy networking.
- **Phase 3:** scoped approvals, guarded adapters and review/recovery.
- **Phase 4:** adversarial testing, property-based checks, CI matrix, static/type/package gates and release documentation.

The defined automated Phase IV gates have passed on the documented CI matrix. This is not the same as a complete production release sign-off. The independent security review, extended stress/fuzzing and broader kernel/AppArmor validation described in [the release checklist](docs/release-checklist.md) are still open.

## 26. Security references

- [Bubblewrap project README and security model](https://github.com/containers/bubblewrap/blob/main/README.md)
- [Bubblewrap security advisories](https://github.com/containers/bubblewrap/security/advisories)
- [Linux kernel Seccomp filter documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [Phase IV security evaluation](docs/security-evaluation-phase4.md)
- [Release checklist and support statement](docs/release-checklist.md)

---

Built as a learning-oriented systems security project. The most important deliverable is not a promise that no attack can succeed; it is a clear enforcement boundary, tested behavior, reproducible evidence and honest documentation of what remains unverified.
