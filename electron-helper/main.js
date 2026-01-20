/**
 * Frame.io OAuth Helper
 * 
 * A minimal Electron app that captures OAuth redirects with custom URL schemes.
 * 
 * How it works:
 * 1. Python writes auth config to ~/.frameio-oauth/args.json
 * 2. This app reads the config and registers as the URL scheme handler
 * 3. Opens browser to the authorization URL
 * 4. When user clicks "Allow" and then "Open FrameioOAuth", we receive the redirect
 * 5. Write the captured URL to ~/.frameio-oauth/result.txt for Python to read
 */

const { app, shell } = require('electron');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Data directory for communication with Python
// Use os.homedir() instead of process.env.HOME for cross-platform reliability
const DATA_DIR = path.join(os.homedir(), '.frameio-oauth');
const ARGS_FILE = path.join(DATA_DIR, 'args.json');
const RESULT_FILE = path.join(DATA_DIR, 'result.txt');

// Timeout (2 minutes)
const TIMEOUT_MS = 120000;
let timeoutHandle;

// Allowed authorization endpoint
const ALLOWED_AUTH_HOST = 'ims-na1.adobelogin.com';

/**
 * Validate that the authorization URL is safe to open.
 * Only allows HTTPS connections to Adobe's auth endpoint.
 */
function isValidAuthUrl(urlString) {
  try {
    const url = new URL(urlString);
    return url.protocol === 'https:' && url.hostname === ALLOWED_AUTH_HOST;
  } catch {
    return false;
  }
}

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

/**
 * Handle the captured OAuth redirect URL
 */
function handleCapturedUrl(url) {
  console.log('CAPTURED_URL:' + url);
  console.error('Captured redirect URL');
  
  // Write to result file for Python
  fs.writeFileSync(RESULT_FILE, url);
  
  // Cleanup and exit
  if (timeoutHandle) clearTimeout(timeoutHandle);
  setTimeout(() => app.quit(), 500);
}

/**
 * Check if we were opened with a URL (from URL scheme handler)
 */
const urlArg = process.argv.find(arg => arg.includes('code=') && arg.includes('://'));
if (urlArg) {
  console.error('Opened with redirect URL');
  handleCapturedUrl(urlArg);
}

/**
 * macOS: Handle URL via open-url event
 */
app.on('open-url', (event, url) => {
  event.preventDefault();
  console.error('Received open-url event');
  handleCapturedUrl(url);
});

/**
 * Single instance lock - ensures only one instance runs
 */
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', (event, argv) => {
    const url = argv.find(arg => arg.includes('code='));
    if (url) {
      handleCapturedUrl(url);
    }
  });
}

/**
 * Main app logic
 */
app.whenReady().then(() => {
  // Hide from dock (run as background app)
  if (app.dock) {
    app.dock.hide();
  }
  
  // Check if result already exists (another instance might have written it)
  if (fs.existsSync(RESULT_FILE)) {
    const result = fs.readFileSync(RESULT_FILE, 'utf8').trim();
    if (result.includes('code=')) {
      console.log('CAPTURED_URL:' + result);
      app.quit();
      return;
    }
  }
  
  // Read configuration from Python
  let urlScheme, authUrl;
  
  if (fs.existsSync(ARGS_FILE)) {
    try {
      const config = JSON.parse(fs.readFileSync(ARGS_FILE, 'utf8'));
      urlScheme = config.urlScheme;
      authUrl = config.authUrl;
    } catch (e) {
      console.error('Failed to read args file:', e.message);
    }
  }
  
  if (!urlScheme || !authUrl) {
    console.error('No configuration found - waiting for URL via open-url event');
    timeoutHandle = setTimeout(() => {
      console.log('ERROR:Timeout waiting for redirect');
      app.quit();
    }, TIMEOUT_MS);
    return;
  }
  
  // Register as the URL scheme handler
  const success = app.setAsDefaultProtocolClient(urlScheme);
  console.error('Registered scheme: ' + urlScheme + ' - ' + (success ? 'OK' : 'FAILED'));
  
  if (!success) {
    console.log('ERROR:Failed to register URL scheme');
    app.quit();
    return;
  }
  
  // Clear any previous result
  if (fs.existsSync(RESULT_FILE)) {
    fs.unlinkSync(RESULT_FILE);
  }
  
  // Validate the authorization URL before opening
  if (!isValidAuthUrl(authUrl)) {
    console.log('ERROR:Invalid authorization URL - must be HTTPS to ' + ALLOWED_AUTH_HOST);
    app.quit();
    return;
  }
  
  // Open the authorization URL in the default browser
  console.error('Opening browser...');
  shell.openExternal(authUrl);
  
  // Poll for result file (in case a new instance writes it)
  const pollInterval = setInterval(() => {
    if (fs.existsSync(RESULT_FILE)) {
      const result = fs.readFileSync(RESULT_FILE, 'utf8').trim();
      if (result.includes('code=')) {
        console.log('CAPTURED_URL:' + result);
        clearInterval(pollInterval);
        if (timeoutHandle) clearTimeout(timeoutHandle);
        app.quit();
      }
    }
  }, 500);
  
  // Set timeout
  timeoutHandle = setTimeout(() => {
    clearInterval(pollInterval);
    console.log('ERROR:Timeout waiting for redirect');
    app.quit();
  }, TIMEOUT_MS);
});

// Keep the app running (no windows)
app.on('window-all-closed', (e) => e.preventDefault());
setInterval(() => {}, 1000);
