"""
Electron-based OAuth redirect capture.

Uses a packaged Electron app to register as a URL scheme handler
and capture OAuth redirects with custom URL schemes.
"""

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse, parse_qs

from rich.console import Console
from rich.panel import Panel

console = Console()

# Paths relative to this file
SRC_DIR = Path(__file__).parent
PROJECT_DIR = SRC_DIR.parent
ELECTRON_HELPER_DIR = PROJECT_DIR / "electron-helper"

# Platform-specific packaged app locations
PACKAGED_APPS = {
    "darwin": ELECTRON_HELPER_DIR / "FrameioOAuth-darwin-universal" / "FrameioOAuth.app",
    "darwin_arm64": ELECTRON_HELPER_DIR / "FrameioOAuth-darwin-arm64" / "FrameioOAuth.app",
    "darwin_x64": ELECTRON_HELPER_DIR / "FrameioOAuth-darwin-x64" / "FrameioOAuth.app",
}

# Data directory for communication with Electron
DATA_DIR = Path.home() / ".frameio-oauth"


def find_packaged_app() -> Optional[Path]:
    """Find the packaged Electron app for the current platform."""
    import platform
    
    system = platform.system().lower()
    
    if system == "darwin":
        # Try universal first, then arch-specific
        for key in ["darwin", "darwin_arm64", "darwin_x64"]:
            if key in PACKAGED_APPS and PACKAGED_APPS[key].exists():
                return PACKAGED_APPS[key]
    
    return None


def check_electron_ready() -> Tuple[bool, str]:
    """
    Check if the Electron helper is ready to use.
    
    Returns:
        (is_ready, message)
    """
    app_path = find_packaged_app()
    if app_path:
        return True, f"Ready: {app_path.name}"
    
    if not ELECTRON_HELPER_DIR.exists():
        return False, "electron-helper directory not found"
    
    package_json = ELECTRON_HELPER_DIR / "package.json"
    if not package_json.exists():
        return False, "package.json not found in electron-helper/"
    
    return False, (
        "Electron app not packaged. Run:\n"
        "  cd electron-helper && npm install && npm run package"
    )


def capture_oauth_redirect(
    url_scheme: str,
    auth_url: str,
    timeout: int = 120,
    verbose: bool = False
) -> Tuple[Optional[str], Optional[str], Optional[dict]]:
    """
    Capture an OAuth redirect using the Electron helper.
    
    The Electron app:
    1. Registers as a handler for the custom URL scheme
    2. Opens the browser to the auth URL
    3. Captures the redirect when user clicks "Open" on the browser prompt
    4. Writes the captured URL to a file for Python to read
    
    Args:
        url_scheme: Full redirect URI (e.g., "adobe+xxx://adobeid/xxx")
        auth_url: The authorization URL to open
        timeout: Seconds to wait for the redirect
    
    Returns:
        (authorization_code, state, error_dict)
    """
    # Extract just the scheme part
    scheme_only = url_scheme.split("://")[0]
    
    # Check if Electron is ready
    is_ready, message = check_electron_ready()
    if not is_ready:
        return None, None, {
            "error": "electron_not_ready",
            "error_description": message
        }
    
    console.print(Panel(
        "[bold]Capturing OAuth redirect with Electron[/bold]\n\n"
        "1. A browser will open for you to sign in\n"
        "2. After clicking 'Allow', your browser will ask to open FrameioOAuth\n"
        "3. [yellow]Click 'Open' to complete authentication[/yellow]",
        title="🔐 OAuth Authentication",
        border_style="blue"
    ))
    
    # Ensure data directory exists with secure permissions (owner-only)
    DATA_DIR.mkdir(exist_ok=True)
    os.chmod(DATA_DIR, 0o700)  # rwx------
    
    # Write args for Electron to read
    args_file = DATA_DIR / "args.json"
    result_file = DATA_DIR / "result.txt"
    
    args_file.write_text(json.dumps({
        "urlScheme": scheme_only,
        "authUrl": auth_url
    }))
    os.chmod(args_file, 0o600)  # rw-------
    
    # Clean previous result
    if result_file.exists():
        result_file.unlink()
    
    if verbose:
        console.print(f"[dim]URL scheme: {scheme_only}[/dim]")
    console.print("\n⏳ Opening browser...")
    
    # Find and run the packaged app
    app_path = find_packaged_app()
    if not app_path:
        return None, None, {
            "error": "app_not_found",
            "error_description": "Could not find packaged Electron app"
        }
    
    # Run the executable directly
    executable = app_path / "Contents" / "MacOS" / "FrameioOAuth"
    
    try:
        process = subprocess.Popen(
            [str(executable)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        console.print("[dim]Waiting for you to sign in and authorize...[/dim]")
        
        # Wait for result file or timeout
        start_time = time.time()
        captured_url = None
        
        while (time.time() - start_time) < timeout:
            # Check result file
            if result_file.exists():
                captured_url = result_file.read_text().strip()
                if "code=" in captured_url:
                    console.print("\n[green]✓ Redirect captured![/green]")
                    break
            
            # Check if process ended
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                
                # Check stdout for captured URL
                for line in stdout.split('\n'):
                    if line.startswith('CAPTURED_URL:'):
                        captured_url = line[len('CAPTURED_URL:'):]
                        console.print("\n[green]✓ Redirect captured![/green]")
                        break
                
                if captured_url:
                    break
                
                # No URL captured, process ended
                break
            
            time.sleep(0.5)
        
        # Cleanup
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        
        # Clean up files
        if result_file.exists():
            result_file.unlink()
        if args_file.exists():
            args_file.unlink()
        
        if not captured_url:
            return None, None, {
                "error": "no_redirect",
                "error_description": "Did not receive redirect within timeout"
            }
        
        # Parse the captured URL
        if verbose:
            console.print(f"[dim]Captured: {captured_url[:80]}...[/dim]")
        
        parsed = urlparse(captured_url)
        params = parse_qs(parsed.query)
        
        if verbose:
            console.print(f"[dim]Params: {list(params.keys())}[/dim]")
        
        if "error" in params:
            return None, None, {
                "error": params["error"][0],
                "error_description": params.get("error_description", ["Unknown error"])[0]
            }
        
        if "code" not in params:
            return None, None, {
                "error": "no_code",
                "error_description": "No authorization code in redirect URL"
            }
        
        code = params["code"][0]
        state = params.get("state", [None])[0]
        
        return code, state, None
        
    except FileNotFoundError:
        return None, None, {
            "error": "executable_not_found",
            "error_description": f"Could not find executable: {executable}"
        }
    except Exception as e:
        return None, None, {
            "error": "unexpected_error",
            "error_description": str(e)
        }
