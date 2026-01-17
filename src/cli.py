#!/usr/bin/env python3
"""
Frame.io OAuth CLI

Command-line interface for authenticating with Frame.io using
Adobe Native App OAuth with PKCE.
"""

import os
import sys
from datetime import datetime
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from auth import (
    authenticate,
    load_tokens,
    clear_tokens,
    get_valid_token,
    TOKEN_FILE,
)
from electron_auth import check_electron_ready

# Load environment variables
load_dotenv()

app = typer.Typer(
    name="frameio-oauth",
    help="Frame.io OAuth CLI - Authenticate with Frame.io using PKCE",
    add_completion=False,
)
console = Console()


def get_config():
    """Get OAuth configuration from environment."""
    client_id = os.getenv("ADOBE_CLIENT_ID")
    redirect_uri = os.getenv("ADOBE_REDIRECT_URI")
    scopes = os.getenv("ADOBE_SCOPES", "email profile openid offline_access")
    
    if not client_id or not redirect_uri:
        console.print(
            Panel(
                "[bold red]Missing configuration![/bold red]\n\n"
                "Please set these environment variables in your .env file:\n"
                "  • ADOBE_CLIENT_ID\n"
                "  • ADOBE_REDIRECT_URI\n"
                "  • ADOBE_SCOPES (optional)\n\n"
                "See env.example for reference.",
                title="⚠️ Configuration Error",
                border_style="red"
            )
        )
        raise typer.Exit(1)
    
    return client_id, redirect_uri, scopes


@app.command()
def auth(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed debug information")
):
    """
    Authenticate with Frame.io using Adobe OAuth + PKCE.
    
    Opens a browser for you to sign in with your Adobe ID.
    After authorization, tokens are saved locally.
    """
    console.print(Panel(
        "[bold]Frame.io OAuth Authentication[/bold]\n\n"
        "This uses Adobe's Native App OAuth flow with PKCE.\n"
        "No client secret required - secure for CLI tools.",
        title="🔐 Authentication",
        border_style="blue"
    ))
    
    # Check Electron helper
    is_ready, message = check_electron_ready()
    if not is_ready:
        console.print(Panel(
            f"[bold red]Electron helper not ready[/bold red]\n\n{message}",
            title="⚠️ Setup Required",
            border_style="red"
        ))
        raise typer.Exit(1)
    
    # Get config
    client_id, redirect_uri, scopes = get_config()
    
    # Only show config details in verbose mode
    if verbose:
        console.print(f"[dim]Client ID: {client_id[:12]}...[/dim]")
        console.print(f"[dim]Redirect: {redirect_uri[:50]}...[/dim]")
        console.print(f"[dim]Scopes: {scopes}[/dim]")
        console.print()
    
    # Authenticate
    access_token, refresh_token, result = authenticate(
        client_id=client_id,
        redirect_uri=redirect_uri,
        scopes=scopes,
        timeout=120,
        verbose=verbose
    )
    
    if access_token:
        expires_at = result.get("expires_at", 0)
        expires_str = datetime.fromtimestamp(expires_at).strftime("%Y-%m-%d %H:%M:%S") if expires_at else "Unknown"
        
        console.print(Panel(
            "[bold green]Authentication successful![/bold green]\n\n"
            f"Token expires: {expires_str}\n"
            f"Refresh token: {'✓ Saved' if refresh_token else '✗ Not provided'}",
            title="✓ Success",
            border_style="green"
        ))
    else:
        error = result or {}
        console.print(Panel(
            f"[bold red]Authentication failed[/bold red]\n\n"
            f"Error: {error.get('error', 'Unknown')}\n"
            f"Details: {error.get('error_description', 'No details')}",
            title="✗ Failed",
            border_style="red"
        ))
        raise typer.Exit(1)


@app.command()
def token():
    """
    Show current token information.
    """
    tokens = load_tokens()
    
    if not tokens:
        console.print(Panel(
            "No tokens found.\n\nRun [bold]auth[/bold] to authenticate.",
            title="Token Status",
            border_style="yellow"
        ))
        raise typer.Exit(1)
    
    # Build info table
    table = Table(title="Token Information")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    
    # Access token (truncated)
    access_token = tokens.get("access_token", "")
    if access_token:
        table.add_row("Access Token", f"{access_token[:20]}...{access_token[-10:]}")
    
    # Refresh token
    refresh_token = tokens.get("refresh_token")
    table.add_row("Refresh Token", "✓ Present" if refresh_token else "✗ Not available")
    
    # Expiration
    expires_at = tokens.get("expires_at", 0)
    if expires_at:
        expires_dt = datetime.fromtimestamp(expires_at)
        is_expired = datetime.now() > expires_dt
        status = "[red]EXPIRED[/red]" if is_expired else "[green]Valid[/green]"
        table.add_row("Expires", f"{expires_dt.strftime('%Y-%m-%d %H:%M:%S')} ({status})")
    
    # Token type
    table.add_row("Token Type", tokens.get("token_type", "Unknown"))
    
    console.print(table)


@app.command()
def test():
    """
    Test the API connection with current tokens.
    """
    client_id, _, _ = get_config()
    
    console.print("Testing Frame.io API connection...")
    
    access_token = get_valid_token(client_id)
    if not access_token:
        console.print(Panel(
            "No valid token available.\n\nRun [bold]auth[/bold] to authenticate.",
            title="⚠️ No Token",
            border_style="yellow"
        ))
        raise typer.Exit(1)
    
    # Test API call
    import httpx
    
    try:
        with httpx.Client() as client:
            response = client.get(
                "https://api.frame.io/v4/me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if response.status_code == 200:
                user = response.json()
                console.print(Panel(
                    "[bold green]API connection successful![/bold green]\n\n"
                    f"User ID: {user.get('id', 'N/A')}\n"
                    f"Email: {user.get('email', 'N/A')}\n"
                    f"Name: {user.get('name', 'N/A')}",
                    title="✓ Connected",
                    border_style="green"
                ))
            else:
                console.print(Panel(
                    f"[bold red]API request failed[/bold red]\n\n"
                    f"Status: {response.status_code}\n"
                    f"Response: {response.text[:200]}",
                    title="✗ Error",
                    border_style="red"
                ))
                raise typer.Exit(1)
                
    except httpx.RequestError as e:
        console.print(f"[red]Request error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def logout():
    """
    Clear saved tokens.
    """
    if TOKEN_FILE.exists():
        clear_tokens()
        console.print("[green]✓ Logged out successfully[/green]")
    else:
        console.print("[yellow]No tokens to clear[/yellow]")


@app.command()
def status():
    """
    Show setup status and configuration.
    """
    console.print(Panel("[bold]Frame.io OAuth Status[/bold]", border_style="blue"))
    
    # Check environment
    console.print("\n[bold]Environment:[/bold]")
    client_id = os.getenv("ADOBE_CLIENT_ID")
    redirect_uri = os.getenv("ADOBE_REDIRECT_URI")
    scopes = os.getenv("ADOBE_SCOPES")
    
    console.print(f"  ADOBE_CLIENT_ID: {'✓ Set' if client_id else '✗ Missing'}")
    console.print(f"  ADOBE_REDIRECT_URI: {'✓ Set' if redirect_uri else '✗ Missing'}")
    console.print(f"  ADOBE_SCOPES: {'✓ Set' if scopes else '(using default)'}")
    
    # Check Electron
    console.print("\n[bold]Electron Helper:[/bold]")
    is_ready, message = check_electron_ready()
    if is_ready:
        console.print(f"  [green]✓ {message}[/green]")
    else:
        console.print(f"  [red]✗ {message}[/red]")
    
    # Check tokens
    console.print("\n[bold]Tokens:[/bold]")
    tokens = load_tokens()
    if tokens:
        expires_at = tokens.get("expires_at", 0)
        if expires_at:
            expires_dt = datetime.fromtimestamp(expires_at)
            is_expired = datetime.now() > expires_dt
            if is_expired:
                console.print("  [yellow]⚠ Token expired[/yellow]")
            else:
                console.print(f"  [green]✓ Valid until {expires_dt.strftime('%Y-%m-%d %H:%M')}[/green]")
        else:
            console.print("  [green]✓ Token present[/green]")
    else:
        console.print("  [dim]No tokens saved[/dim]")


if __name__ == "__main__":
    app()
