"""Command-line interface for agent-boundary (Phase 1 Core Control Plane)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from agent_boundary import __version__
from agent_boundary.audit.report import generate_session_report
from agent_boundary.audit.verifier import verify_audit_log
from agent_boundary.exit_codes import ExitCode
from agent_boundary.policy.engine import ActionRequest, PolicyEngine
from agent_boundary.policy.parser import PolicyValidationError, load_policy
from agent_boundary.policy.schema import Decision
from agent_boundary.simulator import load_scenario, run_simulation
from agent_boundary.sandbox.bwrap import ResourceLimits, SandboxError, run_sandboxed

app = typer.Typer(
    name="agent-boundary",
    help=(
        "Linux-first security supervisor and policy firewall for AI coding agents. "
        "(Phase 1: Policy Validation, Simulation, and Tamper-Evident Audit Core)"
    ),
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"agent-boundary version {__version__}")
        raise typer.Exit(code=int(ExitCode.OK))


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-V",
            help="Show agent-boundary version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """agent-boundary CLI root callback."""


@app.command("validate-policy")
def validate_policy_cmd(
    policy_path: Annotated[Path, typer.Argument(help="Path to YAML policy file.")],
) -> None:
    """Validate a policy file against the strict v1.0 schema (fails closed on unknown fields)."""
    try:
        doc = load_policy(policy_path)
    except PolicyValidationError as exc:
        console.print(f"[bold red]POLICY VALIDATION FAILED:[/bold red] {exc}")
        raise typer.Exit(code=int(ExitCode.CONFIG_OR_POLICY_ERROR)) from exc

    fs_count = (
        len(doc.filesystem.deny)
        + len(doc.filesystem.require_approval)
        + len(doc.filesystem.allow)
    )
    cmd_count = (
        len(doc.commands.deny) + len(doc.commands.require_approval) + len(doc.commands.allow)
    )
    net_count = len(doc.network.deny) + len(doc.network.require_approval) + len(doc.network.allow)

    console.print(
        f"[bold green]VALID POLICY:[/bold green] id='{doc.policy_id}' "
        f"(schema_version={doc.schema_version}, default={doc.default_decision.value}, "
        f"rules: filesystem={fs_count}, commands={cmd_count}, network={net_count})"
    )


@app.command("evaluate")
def evaluate_cmd(
    policy: Annotated[Path, typer.Option("--policy", "-p", help="Path to YAML policy file.")],
    category: Annotated[
        str, typer.Option("--category", "-c", help="Action category: filesystem|command|network.")
    ],
    operation: Annotated[
        str,
        typer.Option(
            "--operation", "-o", help="Operation: read|write|delete|execute|exec|connect."
        ),
    ],
    target: Annotated[
        str, typer.Option("--target", "-t", help="Target path, command, or host:port.")
    ],
    workspace: Annotated[
        str | None, typer.Option("--workspace", "-w", help="Override workspace root path.")
    ] = None,
    symlink_target: Annotated[
        str | None,
        typer.Option("--symlink-target", help="Optional resolved symlink target path."),
    ] = None,
) -> None:
    """Evaluate a single agent action deterministically against a policy (no OS execution)."""
    try:
        doc = load_policy(policy)
    except PolicyValidationError as exc:
        console.print(f"[bold red]POLICY ERROR:[/bold red] {exc}")
        raise typer.Exit(code=int(ExitCode.CONFIG_OR_POLICY_ERROR)) from exc

    engine = PolicyEngine(doc, workspace_override=workspace)
    result = engine.evaluate(
        ActionRequest(
            category=category,
            operation=operation,
            target=target,
            symlink_target=symlink_target,
        )
    )

    console.print(
        f"[bold yellow][POLICY EVALUATION ONLY — NO OS EXECUTION][/bold yellow]\n"
        f"Decision: [bold]{result.decision.value.upper()}[/bold]\n"
        f"Matched Rule: {result.matched_rule_id}\n"
        f"Normalized Target: {result.normalized_target}\n"
        f"Reason: {result.reason}"
    )
    if result.decision is not Decision.ALLOW:
        raise typer.Exit(code=int(ExitCode.POLICY_DENIED))


@app.command("simulate")
def simulate_cmd(
    policy: Annotated[Path, typer.Option("--policy", "-p", help="Path to YAML policy file.")],
    scenario: Annotated[
        Path, typer.Option("--scenario", "-s", help="Path to JSON simulation scenario.")
    ],
    output_dir: Annotated[
        Path, typer.Option("--output-dir", "-d", help="Directory for audit.jsonl and report.")
    ],
) -> None:
    """Run a deterministic mock-agent scenario in clearly labelled Simulation Mode."""
    try:
        doc = load_policy(policy)
    except PolicyValidationError as exc:
        console.print(f"[bold red]POLICY ERROR:[/bold red] {exc}")
        raise typer.Exit(code=int(ExitCode.CONFIG_OR_POLICY_ERROR)) from exc

    try:
        scen = load_scenario(scenario)
    except ValueError as exc:
        console.print(f"[bold red]SCENARIO ERROR:[/bold red] {exc}")
        raise typer.Exit(code=int(ExitCode.CONFIG_OR_POLICY_ERROR)) from exc

    try:
        summary = run_simulation(policy=doc, scenario=scen, output_dir=output_dir)
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]SIMULATION FAILED:[/bold red] {exc}")
        raise typer.Exit(code=int(ExitCode.CONFIG_OR_POLICY_ERROR)) from exc

    console.print(
        "[bold yellow]====================================================================[/bold yellow]"
    )
    console.print(
        "[bold yellow][SIMULATION MODE — NO OS ENFORCEMENT][/bold yellow] "
        "Evaluating policy logic & audit chain only."
    )
    console.print(
        "[bold yellow]====================================================================[/bold yellow]"
    )

    table = Table(title=f"Simulation Session: {summary.session_id}")
    table.add_column("Step ID")
    table.add_column("Action")
    table.add_column("Target")
    table.add_column("Normalized Target")
    table.add_column("Decision")
    table.add_column("Rule ID")

    for step, res in summary.results:
        table.add_row(
            step.action_id,
            f"{step.category}:{step.operation}",
            step.target,
            res.normalized_target,
            res.decision.value.upper(),
            res.matched_rule_id,
        )

    console.print(table)
    console.print(f"Audit Log: [bold]{summary.audit_log_path}[/bold]")
    console.print(f"Report:    [bold]{summary.report_path}[/bold]")
    console.print(f"Head Hash: [bold]{summary.head_hash}[/bold]")

    if summary.expectation_mismatches:
        console.print("[bold red]Expectation Mismatches Detected:[/bold red]")
        for mismatch in summary.expectation_mismatches:
            console.print(f"  - {mismatch}")
        raise typer.Exit(code=int(ExitCode.POLICY_DENIED))

@app.command("run", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def run_sandbox_cmd(
    ctx: typer.Context,
    workspace: Annotated[
        Path, typer.Option("--workspace", "-w", help="Source project directory to copy into the sandbox.")
    ],
    output_root: Annotated[
        Path | None,
        typer.Option("--output-root", help="Parent directory for private session artifacts; must be outside the workspace."),
    ] = None,
    timeout: Annotated[int, typer.Option("--timeout", min=1, max=86400, help="Wall-clock timeout in seconds.")] = 600,
    cpu_seconds: Annotated[int, typer.Option("--cpu-seconds", min=1, max=86400, help="Per-process CPU time limit.")] = 600,
    memory_mib: Annotated[int, typer.Option("--memory-mib", min=256, max=65536, help="Virtual address-space limit in MiB.")] = 4096,
    file_size_mib: Annotated[int, typer.Option("--file-size-mib", min=1, max=4096, help="Maximum size of a single output file in MiB.")] = 512,
    open_files: Annotated[int, typer.Option("--open-files", min=64, max=65536, help="Open file descriptor limit per process.")] = 1024,
) -> None:
    """Run a command inside a real Linux Bubblewrap sandbox with networking disabled.

    Put the child command after --, for example: run --workspace ./project -- /bin/sh -c 'id; pwd'.
    The project is copied into a private session directory. Changes are not copied back automatically.
    """
    command = list(ctx.args)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        console.print("[bold red]ERROR:[/bold red] Supply the command after --.")
        raise typer.Exit(code=int(ExitCode.CONFIG_OR_POLICY_ERROR))

    try:
        result = run_sandboxed(
            workspace=workspace,
            command=command,
            output_root=output_root,
            limits=ResourceLimits(
                timeout_seconds=timeout,
                cpu_seconds=cpu_seconds,
                memory_mib=memory_mib,
                file_size_mib=file_size_mib,
                open_files=open_files,
            ),
        )
    except (OSError, ValueError, SandboxError) as exc:
        console.print(f"[bold red]SANDBOX SETUP FAILED:[/bold red] {exc}")
        raise typer.Exit(code=int(ExitCode.SANDBOX_FAILURE)) from exc

    if result.sandbox_started:
        console.print("\n[bold green][BUBBLEWRAP SANDBOX CHILD STARTED][/bold green]")
        console.print("Outbound network is disabled; host environment variables are not passed through.")
        console.print("The source workspace was not modified. Review the staged copy to inspect changes.")
    else:
        console.print("\n[bold red][SANDBOX NOT STARTED — TARGET COMMAND NOT RUN][/bold red]")
        if result.error:
            console.print(result.error)

    console.print(f"Session: {result.session_id}")
    console.print(f"Evidence directory: {result.session_dir}")
    console.print(f"Report: {result.session_dir / 'session_report.md'}")
    console.print(f"Audit log: {result.session_dir / 'audit.jsonl'}")
    console.print(f"Audit head hash: {result.audit_head_hash}")
    if result.workspace_copy is not None:
        console.print(f"Private workspace copy: {result.workspace_copy}")
        console.print(f"Pre-existing secret-like paths omitted: {result.omitted_secrets}")
        console.print(f"Changed staged paths: {sum(len(result.changes[k]) for k in ('added', 'modified', 'deleted'))}")
    if result.error:
        console.print(f"[yellow]Notice:[/yellow] {result.error}")
    raise typer.Exit(code=result.exit_code)


@app.command("verify-audit")
def verify_audit_cmd(
    audit_path: Annotated[Path, typer.Argument(help="Path to audit.jsonl file.")],
    expected_head_hash: Annotated[
        str | None,
        typer.Option(
            "--expected-head-hash",
            help="Expected final event_hash to detect truncation/re-chaining.",
        ),
    ] = None,
    require_hmac: Annotated[
        bool,
        typer.Option(
            "--require-hmac", help="Require every record to carry a valid HMAC signature."
        ),
    ] = False,
) -> None:
    """Verify hash-chain continuity and tamper evidence of an audit.jsonl log."""
    res = verify_audit_log(
        log_path=audit_path,
        expected_head_hash=expected_head_hash,
        require_hmac=require_hmac,
    )
    for warning in res.warnings:
        console.print(f"[yellow]WARNING:[/yellow] {warning}")

    if not res.valid:
        console.print(f"[bold red]AUDIT VERIFICATION FAILED ({audit_path}):[/bold red]")
        for err in res.errors:
            console.print(f"  - {err}")
        raise typer.Exit(code=int(ExitCode.AUDIT_TAMPER_DETECTED))

    console.print(
        f"[bold green]AUDIT VERIFIED:[/bold green] {res.records_checked} events intact "
        f"(head_hash={res.head_hash}, hmac_verified={res.hmac_verified}, "
        f"head_anchored={res.head_hash_anchored})"
    )


@app.command("report")
def report_cmd(
    session_dir: Annotated[
        Path, typer.Argument(help="Session directory containing audit.jsonl.")
    ],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Optional path to write Markdown report.")
    ] = None,
) -> None:
    """Generate a human-readable Markdown report from a session directory."""
    audit_file = session_dir / "audit.jsonl"
    if not audit_file.exists():
        console.print(f"[bold red]ERROR:[/bold red] No audit.jsonl found in {session_dir}")
        raise typer.Exit(code=int(ExitCode.CONFIG_OR_POLICY_ERROR))

    report_md = generate_session_report(session_dir)
    if output is not None:
        output.write_text(report_md, encoding="utf-8")
        console.print(f"Report written to {output}")
    else:
        console.print(report_md)


if __name__ == "__main__":
    app()
