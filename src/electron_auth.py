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
# On macOS: returns .app bundle path
# On Linux: returns directory containing the executable
# On Windows: returns directory containing the .exe
PACKAGED_APPS = {
    # macOS
    "darwin": ELECTRON_HELPER_DIR / "FrameioOAuth-darwin-universal" / "FrameioOAuth.app",
    "darwin_arm64": ELECTRON_HELPER_DIR / "FrameioOAuth-darwin-arm64" / "FrameioOAuth.app",
    "darwin_x64": ELECTRON_HELPER_DIR / "FrameioOAuth-darwin-x64" / "FrameioOAuth.app",
    # Linux
    "linux_x64": ELECTRON_HELPER_DIR / "FrameioOAuth-linux-x64",
    "linux_arm64": ELECTRON_HELPER_DIR / "FrameioOAuth-linux-arm64",
    # Windows
    "win32_x64": ELECTRON_HELPER_DIR / "FrameioOAuth-win32-x64",
}

# Data directory for communication with Electron
DATA_DIR = Path.home() / ".frameio-oauth"


def register_linux_url_scheme(url_scheme: str, executable_path: Path, verbose: bool = False) -> bool:
    """
    Register a custom URL scheme handler on Linux by creating a .desktop file.
    
    Args:
        url_scheme: The URL scheme to register (e.g., "adobe+xxx")
        executable_path: Path to the Electron executable
        verbose: Whether to print debug output
    
    Returns:
        True if registration succeeded, False otherwise
    """
    applications_dir = Path.home() / ".local" / "share" / "applications"
    applications_dir.mkdir(parents=True, exist_ok=True)
    
    desktop_file = applications_dir / "frameio-oauth.desktop"
    
    # Create the .desktop file content
    desktop_content = f"""[Desktop Entry]
Name=FrameioOAuth
Comment=Frame.io OAuth redirect handler
Exec={executable_path} --no-sandbox %u
Type=Application
Terminal=false
NoDisplay=true
MimeType=x-scheme-handler/{url_scheme};
"""
    
    try:
        desktop_file.write_text(desktop_content)
        if verbose:
            console.print(f"[dim]Created desktop file: {desktop_file}[/dim]")
        
        # Register with xdg-mime
        result = subprocess.run(
            ["xdg-mime", "default", "frameio-oauth.desktop", f"x-scheme-handler/{url_scheme}"],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            if verbose:
                console.print(f"[yellow]xdg-mime warning: {result.stderr}[/yellow]")
        
        # Update the desktop database
        subprocess.run(
            ["update-desktop-database", str(applications_dir)],
            capture_output=True,
            text=True
        )
        
        if verbose:
            console.print(f"[dim]Registered URL scheme handler: {url_scheme}[/dim]")
        
        return True
        
    except Exception as e:
        if verbose:
            console.print(f"[yellow]Failed to register URL scheme: {e}[/yellow]")
        return False


def find_packaged_app() -> Optional[Path]:
    """Find the packaged Electron app for the current platform."""
    import platform
    
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    if system == "darwin":
        # Try universal first, then arch-specific
        for key in ["darwin", "darwin_arm64", "darwin_x64"]:
            if key in PACKAGED_APPS and PACKAGED_APPS[key].exists():
                return PACKAGED_APPS[key]
    elif system == "linux":
        # Determine architecture
        arch = "arm64" if machine in ("aarch64", "arm64") else "x64"
        key = f"linux_{arch}"
        if key in PACKAGED_APPS and PACKAGED_APPS[key].exists():
            return PACKAGED_APPS[key]
        # Fallback to x64 if arm64 not available
        if PACKAGED_APPS["linux_x64"].exists():
            return PACKAGED_APPS["linux_x64"]
    elif system == "windows":
        if PACKAGED_APPS["win32_x64"].exists():
            return PACKAGED_APPS["win32_x64"]
    
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
    
    import platform
    system = platform.system().lower()
    
    if system == "darwin":
        package_cmd = "npm run package"
    elif system == "linux":
        package_cmd = "npm run package:linux"
    elif system == "windows":
        package_cmd = "npm run package:win"
    else:
        package_cmd = "npm run package"
    
    return False, (
        f"Electron app not packaged. Run:\n"
        f"  cd electron-helper && npm install && {package_cmd}"
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
    if verbose:
        console.print(f"[dim]Home directory: {Path.home()}[/dim]")
        console.print(f"[dim]Data directory: {DATA_DIR}[/dim]")
    
    try:
        DATA_DIR.mkdir(exist_ok=True)
        os.chmod(DATA_DIR, 0o700)  # rwx------
    except Exception as e:
        return None, None, {
            "error": "dir_creation_failed",
            "error_description": f"Failed to create data directory {DATA_DIR}: {e}"
        }
    
    # Write args for Electron to read
    args_file = DATA_DIR / "args.json"
    result_file = DATA_DIR / "result.txt"
    
    try:
        args_file.write_text(json.dumps({
            "urlScheme": scheme_only,
            "authUrl": auth_url
        }))
        os.chmod(args_file, 0o600)  # rw-------
        if verbose:
            console.print(f"[dim]Wrote config to: {args_file}[/dim]")
    except Exception as e:
        return None, None, {
            "error": "config_write_failed",
            "error_description": f"Failed to write config file: {e}"
        }
    
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
    
    # Determine executable path based on platform
    import platform
    system = platform.system().lower()
    
    if system == "darwin":
        # macOS: inside .app bundle
        executable = app_path / "Contents" / "MacOS" / "FrameioOAuth"
    elif system == "linux":
        # Linux: executable directly in the directory
        executable = app_path / "FrameioOAuth"
        
        # On Linux, register the URL scheme via .desktop file before launching
        # Electron's setAsDefaultProtocolClient doesn't work reliably on Linux
        if not register_linux_url_scheme(scheme_only, executable, verbose):
            console.print("[yellow]Warning: Could not register URL scheme automatically[/yellow]")
    elif system == "windows":
        # Windows: .exe in the directory
        executable = app_path / "FrameioOAuth.exe"
    else:
        return None, None, {
            "error": "unsupported_platform",
            "error_description": f"Platform '{system}' is not yet supported"
        }
    
    try:
        # Build command with platform-specific flags
        cmd = [str(executable)]
        
        # On Linux, disable the Chrome sandbox to avoid SUID permission issues
        # This is safe for a CLI tool that only handles OAuth redirects
        if system == "linux":
            cmd.append("--no-sandbox")
        
        if verbose:
            console.print(f"[dim]Launching: {' '.join(cmd)}[/dim]")
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Give Electron a moment to start and check for immediate failures
        time.sleep(1)
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            error_msg = stderr.strip() if stderr else stdout.strip()
            return None, None, {
                "error": "electron_crashed",
                "error_description": f"Electron exited immediately: {error_msg}"
            }
        
        if verbose:
            console.print("[dim]Electron started successfully[/dim]")
        
        console.print("[dim]Waiting for you to sign in and authorize...[/dim]")
        
        # Wait for result file or timeout
        start_time = time.time()
        captured_url = None
        last_stderr_check = 0
        
        while (time.time() - start_time) < timeout:
            # In verbose mode, periodically check stderr for debug output
            if verbose and (time.time() - last_stderr_check) > 2:
                import select
                if select.select([process.stderr], [], [], 0)[0]:
                    stderr_line = process.stderr.readline()
                    if stderr_line:
                        console.print(f"[dim]Electron: {stderr_line.strip()}[/dim]")
                last_stderr_check = time.time()
            
            # Check result file
            if result_file.exists():
                captured_url = result_file.read_text().strip()
                if "code=" in captured_url:
                    console.print("\n[green]✓ Redirect captured![/green]")
                    break
            
            # Check if process ended
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                
                # Show any remaining stderr in verbose mode
                if verbose and stderr:
                    for line in stderr.strip().split('\n'):
                        console.print(f"[dim]Electron: {line}[/dim]")
                
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
            # Try to get any remaining output from Electron for debugging
            if process.poll() is None:
                process.terminate()
                try:
                    stdout, stderr = process.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()
            else:
                stdout, stderr = process.communicate()
            
            if verbose and stderr:
                console.print("[yellow]Electron stderr output:[/yellow]")
                for line in stderr.strip().split('\n'):
                    console.print(f"[dim]  {line}[/dim]")
            if verbose and stdout:
                console.print("[yellow]Electron stdout output:[/yellow]")
                for line in stdout.strip().split('\n'):
                    console.print(f"[dim]  {line}[/dim]")
            
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
