"""
PKCE (Proof Key for Code Exchange) implementation.

PKCE is used for OAuth 2.0 public clients (native apps, SPAs) that cannot
securely store a client secret. It prevents authorization code interception attacks.

Flow:
1. Generate random code_verifier (43-128 chars)
2. Create code_challenge = BASE64URL(SHA256(code_verifier))
3. Send code_challenge with authorization request
4. Send code_verifier when exchanging code for tokens
5. Server verifies SHA256(code_verifier) == code_challenge
"""

import base64
import hashlib
import secrets
from typing import Tuple


def generate_code_verifier(length: int = 64) -> str:
    """
    Generate a cryptographically random code verifier.
    
    Args:
        length: Length of the verifier (43-128, default 64)
    
    Returns:
        URL-safe base64 encoded random string
    """
    # Generate random bytes
    random_bytes = secrets.token_bytes(length)
    # Encode as URL-safe base64 (no padding)
    verifier = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
    return verifier[:128]  # Ensure max 128 chars


def generate_code_challenge(code_verifier: str) -> str:
    """
    Generate a code challenge from a code verifier using SHA256.
    
    Args:
        code_verifier: The code verifier string
    
    Returns:
        URL-safe base64 encoded SHA256 hash
    """
    # SHA256 hash the verifier
    digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    # Encode as URL-safe base64 (no padding)
    challenge = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
    return challenge


def generate_state() -> str:
    """
    Generate a random state parameter for CSRF protection.
    
    Returns:
        Random hex string
    """
    return secrets.token_hex(32)


def generate_pkce_pair() -> Tuple[str, str, str]:
    """
    Generate a complete PKCE pair plus state.
    
    Returns:
        Tuple of (code_verifier, code_challenge, state)
    """
    verifier = generate_code_verifier()
    challenge = generate_code_challenge(verifier)
    state = generate_state()
    return verifier, challenge, state
