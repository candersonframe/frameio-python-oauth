"""
Adobe IMS OAuth authentication with PKCE for Frame.io.

Handles the Native App OAuth flow using custom URL scheme redirects.
"""

import json
import os
import time
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from urllib.parse import urlencode, urlparse, parse_qs

import httpx
from rich.console import Console
from rich.panel import Panel

try:
    from .pkce import generate_pkce_pair
except ImportError:
    from pkce import generate_pkce_pair

console = Console()

# Adobe IMS endpoints
AUTH_URL = "https://ims-na1.adobelogin.com/ims/authorize/v2"
TOKEN_URL = "https://ims-na1.adobelogin.com/ims/token/v3"

# Token storage
TOKEN_FILE = Path.home() / ".frameio-tokens.json"


def build_auth_url(
    client_id: str,
    redirect_uri: str,
    scopes: str,
    code_challenge: str,
    state: str
) -> str:
    """
    Build the Adobe IMS authorization URL.
    
    Args:
        client_id: Your application's client ID
        redirect_uri: The registered redirect URI
        scopes: Space-separated OAuth scopes
        code_challenge: PKCE code challenge
        state: Random state for CSRF protection
    
    Returns:
        Complete authorization URL
    """
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "response_type": "code",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{AUTH_URL}?{urlencode(params)}"


def exchange_code_for_tokens(
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str
) -> Dict[str, Any]:
    """
    Exchange authorization code for access and refresh tokens.
    
    Args:
        code: The authorization code from the redirect
        client_id: Your application's client ID
        redirect_uri: The registered redirect URI
        code_verifier: The PKCE code verifier
    
    Returns:
        Token response containing access_token, refresh_token, etc.
    
    Raises:
        Exception: If token exchange fails
    """
    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code": code,
        "code_verifier": code_verifier,
    }
    
    with httpx.Client() as client:
        response = client.post(
            TOKEN_URL,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        if response.status_code != 200:
            error_data = response.json() if response.text else {}
            raise Exception(
                f"Token exchange failed: {response.status_code} - "
                f"{error_data.get('error_description', response.text)}"
            )
        
        return response.json()


def refresh_access_token(
    refresh_token: str,
    client_id: str
) -> Dict[str, Any]:
    """
    Refresh an expired access token.
    
    Args:
        refresh_token: The refresh token
        client_id: Your application's client ID
    
    Returns:
        New token response
    
    Raises:
        Exception: If refresh fails
    """
    data = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
    }
    
    with httpx.Client() as client:
        response = client.post(
            TOKEN_URL,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        if response.status_code != 200:
            error_data = response.json() if response.text else {}
            raise Exception(
                f"Token refresh failed: {response.status_code} - "
                f"{error_data.get('error_description', response.text)}"
            )
        
        return response.json()


def save_tokens(token_data: Dict[str, Any]) -> None:
    """Save tokens to disk with restricted permissions."""
    # Add timestamp for expiration tracking
    token_data["saved_at"] = int(time.time())
    if "expires_in" in token_data:
        token_data["expires_at"] = int(time.time()) + int(token_data["expires_in"])
    
    TOKEN_FILE.write_text(json.dumps(token_data, indent=2))
    # Restrict file permissions to owner only (0o600 = rw-------)
    os.chmod(TOKEN_FILE, 0o600)
    console.print(f"Token saved to {TOKEN_FILE} (permissions: owner-only)")


def load_tokens() -> Optional[Dict[str, Any]]:
    """Load tokens from disk."""
    if not TOKEN_FILE.exists():
        return None
    
    try:
        return json.loads(TOKEN_FILE.read_text())
    except (json.JSONDecodeError, IOError):
        return None


def clear_tokens() -> None:
    """Remove saved tokens."""
    if TOKEN_FILE.exists():
        TOKEN_FILE.unlink()
        console.print("Tokens cleared.")


def get_valid_token(client_id: str) -> Optional[str]:
    """
    Get a valid access token, refreshing if necessary.
    
    Args:
        client_id: Your application's client ID
    
    Returns:
        Valid access token or None
    """
    tokens = load_tokens()
    if not tokens:
        return None
    
    # Check if token is expired (with 5 min buffer)
    expires_at = tokens.get("expires_at", 0)
    if time.time() > (expires_at - 300):
        # Token expired or expiring soon, try to refresh
        refresh_token = tokens.get("refresh_token")
        if refresh_token:
            try:
                console.print("[dim]Refreshing access token...[/dim]")
                new_tokens = refresh_access_token(refresh_token, client_id)
                # Preserve refresh token if not returned
                if "refresh_token" not in new_tokens:
                    new_tokens["refresh_token"] = refresh_token
                save_tokens(new_tokens)
                return new_tokens.get("access_token")
            except Exception as e:
                console.print(f"[yellow]Token refresh failed: {e}[/yellow]")
                return None
        return None
    
    return tokens.get("access_token")


def is_headless() -> bool:
    """
    Detect if running in a headless environment (no display).
    
    Returns:
        True if headless, False if display is available
    """
    import platform
    system = platform.system().lower()
    
    if system == "linux":
        # Check for DISPLAY or WAYLAND_DISPLAY
        display = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
        return not display
    elif system == "darwin":
        # macOS always has a display (even via SSH, you can use pbcopy etc.)
        return False
    elif system == "windows":
        # Windows typically has a display
        return False
    
    return False


def authenticate_headless(
    client_id: str,
    redirect_uri: str,
    scopes: str,
    verbose: bool = False
) -> Tuple[Optional[str], Optional[str], Optional[Dict[str, Any]]]:
    """
    Perform OAuth authentication in headless/manual mode.
    
    User manually opens the URL in their browser and pastes back
    the redirect URL after authorization.
    
    Args:
        client_id: Your application's client ID
        redirect_uri: The registered redirect URI (custom URL scheme)
        scopes: Space-separated OAuth scopes
        verbose: Show debug output
    
    Returns:
        Tuple of (access_token, refresh_token, token_info) or (None, None, error_dict)
    """
    from rich.prompt import Prompt
    
    # Generate PKCE parameters
    code_verifier, code_challenge, state = generate_pkce_pair()
    
    # Build authorization URL
    auth_url = build_auth_url(client_id, redirect_uri, scopes, code_challenge, state)
    
    console.print(Panel(
        "[bold]Headless/Manual Authentication Mode[/bold]\n\n"
        "Since no display is available (or --headless was specified),\n"
        "you'll need to complete authentication manually.",
        title="🔐 Manual OAuth Flow",
        border_style="blue"
    ))
    
    console.print("\n[bold]Step 1:[/bold] Open this URL in a browser (on any device):\n")
    console.print(Panel(auth_url, title="Authorization URL", border_style="cyan"))
    
    console.print("\n[bold]Step 2:[/bold] Sign in and click 'Allow' to authorize the application.")
    
    console.print("\n[bold]Step 3:[/bold] After authorization, your browser will try to open a URL starting with:")
    console.print(f"         [cyan]{redirect_uri.split('://')[0]}://...[/cyan]")
    console.print("         The browser may show an error since it can't handle this URL scheme.")
    console.print("         [bold yellow]Copy the complete URL from your browser's address bar.[/bold yellow]")
    
    console.print()
    redirect_url = Prompt.ask("[bold]Paste the redirect URL here[/bold]")
    
    if not redirect_url:
        return None, None, {
            "error": "no_input",
            "error_description": "No redirect URL provided"
        }
    
    # Parse the redirect URL
    try:
        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)
        
        if verbose:
            console.print(f"[dim]Parsed URL params: {list(params.keys())}[/dim]")
        
        # Check for errors
        if "error" in params:
            return None, None, {
                "error": params["error"][0],
                "error_description": params.get("error_description", ["Authorization denied"])[0]
            }
        
        # Get authorization code
        if "code" not in params:
            return None, None, {
                "error": "no_code",
                "error_description": "No authorization code found in the URL. Make sure you copied the complete URL."
            }
        
        code = params["code"][0]
        returned_state = params.get("state", [None])[0]
        
        # Verify state
        if returned_state != state:
            return None, None, {
                "error": "state_mismatch",
                "error_description": "State parameter mismatch - possible CSRF attack. Authentication aborted."
            }
        
    except Exception as e:
        return None, None, {
            "error": "parse_error",
            "error_description": f"Failed to parse redirect URL: {e}"
        }
    
    # Exchange code for tokens
    console.print("\n✓ Authorization code received, exchanging for token...")
    
    try:
        token_data = exchange_code_for_tokens(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier
        )
        
        save_tokens(token_data)
        
        return (
            token_data.get("access_token"),
            token_data.get("refresh_token"),
            token_data
        )
        
    except Exception as e:
        return None, None, {"error": "token_exchange", "error_description": str(e)}


def authenticate(
    client_id: str,
    redirect_uri: str,
    scopes: str,
    timeout: int = 120,
    verbose: bool = False,
    headless: bool = False
) -> Tuple[Optional[str], Optional[str], Optional[Dict[str, Any]]]:
    """
    Perform the complete OAuth authentication flow.
    
    Args:
        client_id: Your application's client ID
        redirect_uri: The registered redirect URI (custom URL scheme)
        scopes: Space-separated OAuth scopes
        timeout: Seconds to wait for redirect
        verbose: Show debug output
        headless: Force headless/manual mode
    
    Returns:
        Tuple of (access_token, refresh_token, token_info) or (None, None, error_dict)
    """
    # Check if we should use headless mode
    use_headless = headless or is_headless()
    
    if use_headless:
        if verbose:
            console.print("[dim]Using headless/manual authentication mode[/dim]")
        return authenticate_headless(client_id, redirect_uri, scopes, verbose)
    
    # Generate PKCE parameters
    code_verifier, code_challenge, state = generate_pkce_pair()
    
    # Build authorization URL
    auth_url = build_auth_url(client_id, redirect_uri, scopes, code_challenge, state)
    
    # Use Electron helper to capture the redirect
    try:
        try:
            from .electron_auth import capture_oauth_redirect
        except ImportError:
            from electron_auth import capture_oauth_redirect
        
        code, returned_state, error = capture_oauth_redirect(
            url_scheme=redirect_uri,
            auth_url=auth_url,
            timeout=timeout,
            verbose=verbose
        )
        
        if error:
            return None, None, error
        
        if returned_state != state:
            return None, None, {
                "error": "state_mismatch",
                "error_description": "State parameter mismatch - possible CSRF attack. Authentication aborted."
            }
        
        if not code:
            return None, None, {"error": "no_code", "error_description": "No authorization code received"}
        
    except ImportError as e:
        return None, None, {"error": "import_error", "error_description": str(e)}
    except Exception as e:
        return None, None, {"error": "auth_error", "error_description": str(e)}
    
    # Exchange code for tokens
    console.print("\n✓ Authorization code received, exchanging for token...")
    
    try:
        token_data = exchange_code_for_tokens(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier
        )
        
        save_tokens(token_data)
        
        return (
            token_data.get("access_token"),
            token_data.get("refresh_token"),
            token_data
        )
        
    except Exception as e:
        return None, None, {"error": "token_exchange", "error_description": str(e)}
