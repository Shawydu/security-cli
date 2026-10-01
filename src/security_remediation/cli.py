"""Local-only CLI; no GitHub write commands exist."""
from pathlib import Path

import typer
from pydantic import ValidationError

from .contracts import Status
from .runner import run as run_local
from .fixture import run_fixture
from .state import Conflict
from .workspace import Rejected

app = typer.Typer(help="Supervised local Python dependency remediation (publication unavailable).")


@app.callback()
def main() -> None:
    """Only local commands are supported."""


@app.command()
def run(
    alert_file: Path = typer.Option(..., exists=True, dir_okay=False),
    source: Path = typer.Option(..., exists=True, file_okay=False),
    policy: Path = typer.Option(..., exists=True, dir_okay=False),
    state_dir: Path = typer.Option(...),
    output: Path = typer.Option(...),
    operation_id: str | None = typer.Option(None, help="Explicit new local operation; requires --new-operation-reason."),
    new_operation_reason: str | None = typer.Option(None, help="Human reason for a new retry ledger; old history remains."),
) -> None:
    try:
        result = run_local(alert_file=alert_file, source=source, policy_file=policy, state_dir=state_dir, output=output, operation_id=operation_id, new_operation_reason=new_operation_reason)
    except Conflict as exc:
        typer.echo(f"state/source conflict: {exc}", err=True)
        raise typer.Exit(40) from exc
    except (Rejected, ValidationError, ValueError) as exc:
        typer.echo(f"blocked by invalid or ineligible input: {exc}", err=True)
        raise typer.Exit(10) from exc
    typer.echo(f"{result.outcome}: {result.reason}; attempts={result.attempts}")
    codes = {Status.VERIFIED: 0, Status.BLOCKED: 10, Status.EXHAUSTED: 20, Status.INTERRUPTED: 30, Status.INFRASTRUCTURE_ERROR: 30, Status.CONFLICT: 40}
    raise typer.Exit(codes.get(result.outcome, 30))


@app.command()
def fixture(
    fixture: Path = typer.Option(..., exists=True, file_okay=False, help="Offline pilot fixture directory."),
    output: Path = typer.Option(...),
    case: str = typer.Option("direct", help="direct, forbidden, scanner-error, baseline-failure"),
) -> None:
    """Run simulated policy cases without model, packages, audit, or network."""
    try:
        result = run_fixture(fixture.resolve(), output.resolve(), case)
    except (Rejected, ValidationError, ValueError) as exc:
        typer.echo(f"invalid fixture: {exc}", err=True)
        raise typer.Exit(40) from exc
    typer.echo(f"simulated {result['outcome']}; no real verification (fixture-result.json)")


if __name__ == "__main__":
    app()
