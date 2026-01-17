# Frame.io Python Native App OAuth with PKCE

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-green.svg)](https://www.python.org/downloads/)
[![Platform: macOS](https://img.shields.io/badge/Platform-macOS-lightgrey.svg)](#platform-support)

A Python CLI tool for authenticating with Frame.io using Adobe's Native App OAuth flow with PKCE (Proof Key for Code Exchange).

This solution uses a hybrid Python + Electron approach to automatically capture custom URL scheme redirects, eliminating the need for manual copy/pasting of authorization codes.

## How It Works

1. **Python** generates the authorization URL with PKCE parameters
2. **Electron helper** registers as a URL scheme handler and opens your browser
3. You sign in and click "Allow access"
4. When prompted "Open FrameioOAuth?", click **Open**
5. Electron captures the redirect and passes it back to Python
6. Python exchanges the code for tokens and saves them

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| **macOS** | ✅ Supported | Universal binary (Intel + Apple Silicon) |
| **Windows** | 🚧 Not yet | Electron helper needs Windows build |
| **Linux** | 🚧 Not yet | Electron helper needs Linux build |

> **Note:** The core Python OAuth logic is cross-platform. Only the Electron helper (for capturing custom URL scheme redirects) is currently macOS-only. Contributions for Windows/Linux support are welcome!

## Prerequisites

- Python 3.9+
- Node.js 18+ (for Electron helper)
- macOS (see [Platform Support](#platform-support))
- A Frame.io Developer Console application with Native App credentials

## Setup

### 1. Clone and install Python dependencies

```bash
cd frameio-python-oauth
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Build the Electron helper

```bash
cd electron-helper
npm install
npm run package
cd ..
```

This creates a `FrameioOAuth.app` that handles the custom URL scheme redirect.

### 3. Configure your credentials

Copy the example environment file and add your credentials:

```bash
cp .env.example .env
```

Edit `.env` with your Frame.io app credentials from the [Adobe Developer Console](https://developer.adobe.com/console):

```
ADOBE_CLIENT_ID=your_client_id_here
ADOBE_REDIRECT_URI=adobe+your_unique_scheme://adobeid/your_client_id
ADOBE_SCOPES="email additional_info.roles profile openid offline_access"
```

## Usage

### Authenticate

```bash
python src/cli.py auth
```

This will:
1. Open your browser to Adobe's sign-in page
2. After you authorize, click "Open" when prompted to open FrameioOAuth
3. Save tokens to `~/.frameio-tokens.json`

For debugging, use the `--verbose` flag to see detailed information:

```bash
python src/cli.py auth --verbose
```

### Test Connection

```bash
python src/cli.py test
```

Verifies your token works by making an API call.

### View Token Info

```bash
python src/cli.py token
```

Shows your current token status and expiration.

### Clear Tokens

```bash
python src/cli.py logout
```

Removes saved tokens.

## Project Structure

```
frameio-python-oauth/
├── README.md
├── requirements.txt
├── .env.example
├── .gitignore
├── src/
│   ├── __init__.py
│   ├── cli.py          # Command-line interface
│   ├── auth.py         # OAuth authentication logic
│   ├── pkce.py         # PKCE helper functions
│   └── electron_auth.py # Electron integration
└── electron-helper/
    ├── package.json
    ├── main.js         # Electron URL scheme handler
    └── FrameioOAuth-darwin-universal/  # Built app (after npm run package)
```

## How PKCE Works

PKCE (Proof Key for Code Exchange) is used instead of a client secret for native/public applications:

1. Generate a random `code_verifier`
2. Create a `code_challenge` = SHA256(code_verifier)
3. Send `code_challenge` with the authorization request
4. Send `code_verifier` when exchanging the code for tokens
5. Adobe verifies that SHA256(code_verifier) matches the original challenge

This prevents authorization code interception attacks.

## Security Considerations

### Token Storage

By default, tokens are stored in `~/.frameio-tokens.json` with owner-only permissions (`0600`). While this is reasonably secure for development and personal use, **for production applications you should use a more secure storage mechanism**:

#### Recommended Alternatives

| Method | Best For | Python Library |
|--------|----------|----------------|
| **System Keychain** | Desktop apps, highest security | [`keyring`](https://pypi.org/project/keyring/) |
| **Encrypted File** | Cross-platform, self-contained | [`cryptography`](https://pypi.org/project/cryptography/) |
| **Environment Variables** | CI/CD, containers | Built-in `os.environ` |
| **Secret Manager** | Cloud deployments | AWS Secrets Manager, GCP Secret Manager, etc. |

#### Example: Using System Keychain

```python
import keyring

# Store token
keyring.set_password("frameio", "access_token", access_token)
keyring.set_password("frameio", "refresh_token", refresh_token)

# Retrieve token
access_token = keyring.get_password("frameio", "access_token")
```

The `keyring` library automatically uses the appropriate secure storage:
- **macOS**: Keychain
- **Windows**: Windows Credential Locker  
- **Linux**: Secret Service API (GNOME Keyring, KWallet)

#### Example: Encrypted File Storage

```python
from cryptography.fernet import Fernet

# Generate key once and store securely (e.g., in keychain)
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt and save
encrypted = cipher.encrypt(json.dumps(tokens).encode())
Path("~/.frameio-tokens.enc").expanduser().write_bytes(encrypted)

# Decrypt and load
encrypted = Path("~/.frameio-tokens.enc").expanduser().read_bytes()
tokens = json.loads(cipher.decrypt(encrypted))
```

### Security Features

This implementation includes several security measures:

- ✅ **PKCE** - Prevents authorization code interception
- ✅ **State Parameter** - Protects against CSRF attacks (authentication aborts on mismatch)
- ✅ **Restricted File Permissions** - Token and IPC files are owner-readable only (`0600`)
- ✅ **Minimal Debug Output** - Sensitive data hidden unless `--verbose` is used
- ✅ **Automatic Token Refresh** - Minimizes exposure of long-lived credentials

### Best Practices

1. **Never commit tokens** - The `.gitignore` excludes token files, but always verify
2. **Rotate credentials** - Use `logout` command when done testing
3. **Use minimal scopes** - Only request the permissions your app needs
4. **Secure your `.env`** - Contains your client ID; don't commit to version control

## Troubleshooting

### "Failed to register URL scheme"
- Make sure you've built the Electron app: `cd electron-helper && npm run package`
- The packaged app needs to be in `electron-helper/FrameioOAuth-darwin-universal/`

### Browser shows "Failed to launch" error
- Click "Open" when the browser asks to open FrameioOAuth
- If the dialog doesn't appear, the URL scheme might not be registered

### Token exchange fails
- Verify your `ADOBE_CLIENT_ID` and `ADOBE_REDIRECT_URI` match your Adobe Console settings
- Make sure scopes include `offline_access` for refresh tokens

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Credits

Built for the Frame.io developer community.
