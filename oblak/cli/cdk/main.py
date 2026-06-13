"""Oblak CDK CLI entry point.

Commands:
    cdk configure --server URL   Set the server URL.
    cdk register                 Create an account.
    cdk login                    Authenticate; stores a bearer token locally (0600).
    cdk logout                   Forget the local token.
    cdk deploy PATH --name NAME  Package a directory and upload it.
    cdk list                     List your deployed functions.
    cdk whoami                   Show current configuration.

Passwords are read interactively (hidden) and never stored or logged.
"""

from __future__ import annotations

import getpass

import typer

from . import config as cfgmod
from .api_client import ApiError, OblakClient
from .packaging import build_package

app = typer.Typer(help="Oblak CDK — deploy and run Python functions on the cloud.")


def _client(require_auth: bool = False) -> OblakClient:
    cfg = cfgmod.load()
    if require_auth and not cfg.access_token:
        typer.secho("Not logged in. Run `cdk login` first.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    return OblakClient(cfg.server_url, token=cfg.access_token)


@app.command()
def configure(
    server: str = typer.Option(..., "--server", help="Server base URL, e.g. https://oblak.example"),
) -> None:
    """Set the server URL used by the CLI."""
    cfg = cfgmod.load()
    cfg.server_url = server
    cfgmod.save(cfg)
    typer.secho(f"Server set to {server}", fg=typer.colors.GREEN)


@app.command()
def register(
    username: str = typer.Option(..., "--username", "-u", prompt=True),
) -> None:
    """Create a new account (password prompted, hidden)."""
    password = getpass.getpass("Password (min 10 chars): ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        typer.secho("Passwords do not match.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    client = _client()
    try:
        client.register(username, password)
    except ApiError as exc:
        typer.secho(f"Registration failed: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    typer.secho("Registered. You can now `cdk login`.", fg=typer.colors.GREEN)


@app.command()
def login(
    username: str = typer.Option(..., "--username", "-u", prompt=True),
) -> None:
    """Authenticate and store a short-lived bearer token locally."""
    password = getpass.getpass("Password: ")
    client = _client()
    try:
        result = client.login(username, password)
    except ApiError as exc:
        typer.secho(f"Login failed: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    cfg = cfgmod.load()
    cfg.username = username
    cfg.access_token = result["access_token"]
    cfg.expires_in = result.get("expires_in")
    cfgmod.save(cfg)
    typer.secho("Logged in. Token stored at ~/.oblak/credentials.json (0600).",
                fg=typer.colors.GREEN)


@app.command()
def logout() -> None:
    """Remove the stored token."""
    cfgmod.clear_token()
    typer.secho("Logged out.", fg=typer.colors.GREEN)


@app.command()
def deploy(
    path: str = typer.Argument(..., help="Directory containing the function code."),
    name: str = typer.Option(..., "--name", "-n", help="Function name."),
) -> None:
    """Package a local directory (incl. requirements.txt) and upload it."""
    try:
        package = build_package(path)
    except ValueError as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(code=1)

    client = _client(require_auth=True)
    try:
        result = client.upload(name, package)
    except ApiError as exc:
        typer.secho(f"Deploy failed: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.secho(
        f"Deployed '{result['name']}' — status={result['status']} "
        f"sha256={result['code_sha256'][:12]}…",
        fg=typer.colors.GREEN,
    )


@app.command(name="list")
def list_functions() -> None:
    """List your deployed functions."""
    client = _client(require_auth=True)
    try:
        items = client.list_functions()
    except ApiError as exc:
        typer.secho(f"List failed: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    if not items:
        typer.echo("No functions deployed yet.")
        return
    for it in items:
        typer.echo(f"- {it['name']:20s} {it['status']:10s} {it['code_sha256'][:12]}…")


@app.command()
def whoami() -> None:
    """Show current CLI configuration."""
    cfg = cfgmod.load()
    typer.echo(f"server : {cfg.server_url}")
    typer.echo(f"user   : {cfg.username or '(not logged in)'}")
    typer.echo(f"token  : {'present' if cfg.access_token else 'none'}")


def main() -> None:  # console-script entry point
    app()


if __name__ == "__main__":
    main()
