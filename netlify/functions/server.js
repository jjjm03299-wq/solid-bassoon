// Netlify Function: server.js (Express wrapped for Netlify Functions with PKCE Account Authorization, App Management, and test sleep utility without hardcoded loopback fallbacks)
const express = require('express');
const serverless = require('serverless-http');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Load or generate JWT secret key oauth-secret.key strictly without fallbacks
const secretKeyPath = path.join(__dirname, 'oauth-secret.key');
let JWT_SECRET;

if (fs.existsSync(secretKeyPath)) {
  JWT_SECRET = fs.readFileSync(secretKeyPath, 'utf8').trim();
} else {
  JWT_SECRET = crypto.randomBytes(64).toString('hex');
  fs.writeFileSync(secretKeyPath, JWT_SECRET, 'utf8');
}

const deviceCodes = new Map();
const pkceChallenges = new Map();
const clients = new Map();
const users = new Map();
const sessions = new Map();

const COUNTRIES = [
  { name: 'United States', code: 'us', flag: '🇺🇸', ip: '198.51.100.45' },
  { name: 'Germany', code: 'de', flag: '🇩🇪', ip: '203.0.113.22' },
  { name: 'Japan', code: 'jp', flag: '🇯🇵', ip: '192.0.2.14' },
  { name: 'United Kingdom', code: 'gb', flag: '🇬🇧', ip: '198.51.100.88' },
  { name: 'Canada', code: 'ca', flag: '🇨🇦', ip: '203.0.113.99' },
  { name: 'Australia', code: 'au', flag: '🇦🇺', ip: '192.0.2.55' },
  { name: 'Singapore', code: 'sg', flag: '🇸🇬', ip: '198.51.100.12' },
  { name: 'France', code: 'fr', flag: '🇫🇷', ip: '203.0.113.77' },
  { name: 'Switzerland', code: 'ch', flag: '🇨🇭', ip: '192.0.2.205' },
  { name: 'Netherlands', code: 'nl', flag: '🇳🇱', ip: '198.51.100.160' }
];

const activeVpnConnections = new Map();
const vpnLogs = [];

// Helper to authenticate JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Forbidden token' });
    req.user = user;
    next();
  });
}

// Test Utility: Sleep / Delay helper function
const sleepMs = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

app.get('/api/test/sleep', async (req, res) => {
  const ms = parseInt(req.query.ms) || 1000;
  await sleepMs(ms);
  res.json({ success: true, slept_ms: ms, timestamp: Date.now() });
});

// OAuth App Management Endpoints
app.post('/oauth/apps', (req, res) => {
  const { name, redirect_uri } = req.body;
  const clientId = 'client_' + crypto.randomBytes(8).toString('hex');
  const clientSecret = 'secret_' + crypto.randomBytes(16).toString('hex');
  
  clients.set(clientId, { name, redirect_uri, clientSecret, createdAt: Date.now() });
  res.json({ client_id: clientId, client_secret: clientSecret });
});

app.get('/oauth/apps', authenticateToken, (req, res) => {
  const appList = Array.from(clients.entries()).map(([id, appData]) => ({
    client_id: id,
    name: appData.name,
    redirect_uri: appData.redirect_uri,
    createdAt: appData.createdAt
  }));
  res.json(appList);
});

app.delete('/oauth/apps', authenticateToken, (req, res) => {
  const { client_id } = req.body;
  if (!clients.has(client_id)) return res.status(404).json({ error: 'Client application not found' });
  clients.delete(client_id);
  res.json({ success: true, message: 'Client application deleted' });
});

// PKCE Authorization Prompt & Handler UI (`const htmlContent` for PKCE Account Selection)
const pkceHtmlContent = (clientId, redirectUri, state, codeChallenge, codeChallengeMethod) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Authorize Account - OAuth PKCE</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen flex items-center justify-center p-6 font-sans">
  <div class="max-w-md w-full bg-slate-800 border border-slate-700 p-6 rounded-lg space-y-6 shadow-xl">
    <div>
      <h1 class="text-xl font-bold tracking-tight">Authorize Application</h1>
      <p class="text-xs text-slate-400 mt-1">Client ID: ${clientId}</p>
    </div>
    <div class="space-y-4">
      <div>
        <label class="block text-xs font-medium text-slate-300 mb-1">Select Account (User Email)</label>
        <input id="authEmail" type="email" placeholder="user@example.com" class="w-full bg-slate-900 border border-slate-700 p-2 rounded text-sm text-slate-100">
      </div>
      <div>
        <label class="block text-xs font-medium text-slate-300 mb-1">Password</label>
        <input id="authPassword" type="password" placeholder="••••••••" class="w-full bg-slate-900 border border-slate-700 p-2 rounded text-sm text-slate-100">
      </div>
      <button onclick="approveAuthorization()" class="w-full bg-indigo-600 hover:bg-indigo-500 py-2.5 rounded font-medium transition text-sm">Approve & Connect Account</button>
    </div>
  </div>
  <script>
    async function approveAuthorization() {
      const email = document.getElementById('authEmail').value;
      const password = document.getElementById('authPassword').value;
      const res = await fetch('/oauth/authorize/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, client_id: '${clientId}', redirect_uri: '${redirectUri}', state: '${state}', code_challenge: '${codeChallenge}', code_challenge_method: '${codeChallengeMethod}' })
      });
      const data = await res.json();
      if (data.redirect_url) {
        window.location.href = data.redirect_url;
      } else {
        alert(data.error || 'Authorization failed');
      }
    }
  </script>
</body>
</html>`;

app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, code_challenge, code_challenge_method, state } = req.query;
  if (!clients.has(client_id)) return res.status(400).json({ error: 'Invalid client_id' });
  res.send(pkceHtmlContent(client_id, redirect_uri, state, code_challenge, code_challenge_method || 'plain'));
});

app.post('/oauth/authorize/submit', (req, res) => {
  const { email, password, client_id, redirect_uri, state, code_challenge, code_challenge_method } = req.body;
  let foundUser = null;
  for (const u of users.values()) {
    if (u.email === email && u.password === password) {
      foundUser = u;
      break;
    }
  }

  if (!foundUser) {
    const userId = 'usr_' + crypto.randomBytes(4).toString('hex');
    foundUser = { id: userId, email, password };
    users.set(userId, foundUser);
  }

  const authCode = 'ac_' + crypto.randomBytes(8).toString('hex');
  pkceChallenges.set(authCode, {
    client_id,
    userId: foundUser.id,
    code_challenge,
    code_challenge_method,
    redirect_uri,
    expiresAt: Date.now() + 600000
  });

  const separator = redirect_uri.includes('?') ? '&' : '?';
  const finalRedirectUrl = `${redirect_uri}${separator}code=${authCode}${state ? `&state=${state}` : ''}`;
  res.json({ redirect_url: finalRedirectUrl });
});

// OAuth Device Code Flow Initialization (50 minutes expiration = 3000 seconds)
app.post('/oauth/device/code', (req, res) => {
  const { client_id } = req.body;
  if (!clients.has(client_id)) return res.status(400).json({ error: 'Invalid client_id' });

  const deviceCode = 'dc_' + crypto.randomBytes(6).toString('hex');
  const userCode = crypto.randomBytes(3).toString('hex').toUpperCase();
  const expiresIn = 3000;

  deviceCodes.set(userCode, {
    deviceCode,
    clientId,
    status: 'pending',
    expiresAt: Date.now() + expiresIn * 1000,
    userId: null
  });

  res.json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: `${req.protocol}://${req.get('host')}/oauth/device`,
    expires_in: expiresIn,
    interval: 5
  });
});

// OAuth Token Endpoint (supports device code polling and PKCE code exchange)
app.post('/oauth2/token', (req, res) => {
  const { grant_type, device_code, code, code_verifier } = req.body;
  
  if (grant_type === 'urn:ietf:params:oauth:grant-type:device_code') {
    let foundEntry = null;
    for (const [, data] of deviceCodes.entries()) {
      if (data.deviceCode === device_code) {
        foundEntry = data;
        break;
      }
    }

    if (!foundEntry) return res.status(400).json({ error: 'invalid_device_code' });
    if (Date.now() > foundEntry.expiresAt) return res.status(400).json({ error: 'expired_token' });
    if (foundEntry.status === 'pending') return res.status(400).json({ error: 'authorization_pending' });
    if (foundEntry.status === 'denied') return res.status(400).json({ error: 'access_denied' });

    const accessToken = jwt.sign({ userId: foundEntry.userId }, JWT_SECRET, { expiresIn: '1h' });
    return res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600 });
  }

  if (grant_type === 'authorization_code') {
    const pkceData = pkceChallenges.get(code);
    if (!pkceData) return res.status(400).json({ error: 'invalid_grant' });
    if (Date.now() > pkceData.expiresAt) return res.status(400).json({ error: 'expired_grant' });

    if (pkceData.code_challenge_method === 'S256') {
      const hash = crypto.createHash('sha256').update(code_verifier).digest('base64url');
      if (hash !== pkceData.code_challenge) return res.status(400).json({ error: 'invalid_code_verifier' });
    } else {
      if (code_verifier !== pkceData.code_challenge) return res.status(400).json({ error: 'invalid_code_verifier' });
    }

    pkceChallenges.delete(code);
    const accessToken = jwt.sign({ userId: pkceData.userId, clientId: pkceData.client_id }, JWT_SECRET, { expiresIn: '1h' });
    return res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600 });
  }

  res.status(400).json({ error: 'unsupported_grant_type' });
});

// OAuth User Info & Status
app.get('/api/oauth/status', authenticateToken, (req, res) => {
  res.json({ status: 'active', user_id: req.user.userId });
});

app.get('/oauth/userinfo', authenticateToken, (req, res) => {
  const user = users.get(req.user.userId) || { id: req.user.userId };
  res.json({ sub: user.id, email: user.email });
});

// Standard Authentication & Identity Routes
app.post('/api/auth/register', (req, res) => {
  const { email, password } = req.body;
  if (users.has(email)) return res.status(400).json({ error: 'User already exists' });

  const userId = 'usr_' + crypto.randomBytes(4).toString('hex');
  users.set(userId, { id: userId, email, password });
  res.json({ message: 'Registered successfully', user_id: userId });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  let foundUser = null;
  for (const u of users.values()) {
    if (u.email === email && u.password === password) {
      foundUser = u;
      break;
    }
  }

  if (!foundUser) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ userId: foundUser.id }, JWT_SECRET, { expiresIn: '1h' });
  sessions.set(token, foundUser.id);
  res.json({ token, user: { id: foundUser.id, email: foundUser.email } });
});

app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.get(req.user.userId);
  res.json({ id: req.user.userId, email: user ? user.email : 'unknown' });
});

// Identity and Aliases (/api/whoami & /api/whoani)
const handleWhoAmI = (req, res) => {
  const user = users.get(req.user.userId);
  res.json({ user_id: req.user.userId, email: user ? user.email : null });
};

app.get('/api/whoami', authenticateToken, handleWhoAmI);
app.get('/api/whoani', authenticateToken, handleWhoAmI);

// Health Check
app.get('/api/healthz', (req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

// Device Prompt Connection Endpoint
app.post('/api/device/connect', authenticateToken, (req, res) => {
  const { user_code } = req.body;
  const entry = deviceCodes.get(user_code);

  if (!entry) return res.status(404).json({ error: 'Invalid user code' });
  if (Date.now() > entry.expiresAt) return res.status(400).json({ error: 'Code expired' });

  entry.status = 'authorized';
  entry.userId = req.user.userId;
  deviceCodes.set(user_code, entry);

  res.json({ success: true, message: 'Device connected successfully' });
});

// VPN Management Endpoints
app.get('/api/vpn/countries', (req, res) => {
  res.json(COUNTRIES);
});

app.post('/api/vpn/connect', authenticateToken, (req, res) => {
  const { country_code } = req.body;
  const country = COUNTRIES.find(c => c.code === country_code);
  if (!country) return res.status(404).json({ error: 'Country not found' });

  const connectionInfo = {
    status: 'connected',
    country: country.name,
    flag: country.flag,
    ip: country.ip,
    connectedAt: new Date().toISOString()
  };

  activeVpnConnections.set(req.user.userId, connectionInfo);
  vpnLogs.push({ userId: req.user.userId, action: 'connect', ...connectionInfo, timestamp: Date.now() });
  
  res.json(connectionInfo);
});

app.post('/api/vpn/disconnect', authenticateToken, (req, res) => {
  const existing = activeVpnConnections.get(req.user.userId);
  if (existing) {
    vpnLogs.push({ userId: req.user.userId, action: 'disconnect', country: existing.country, timestamp: Date.now() });
  }
  activeVpnConnections.delete(req.user.userId);
  res.json({ status: 'disconnected' });
});

app.get('/api/vpn/status', authenticateToken, (req, res) => {
  const connection = activeVpnConnections.get(req.user.userId) || { status: 'disconnected' };
  res.json(connection);
});

app.get('/api/vpn/ip', authenticateToken, (req, res) => {
  const connection = activeVpnConnections.get(req.user.userId);
  if (!connection) {
    return res.json({ ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown', status: 'direct' });
  }
  res.json({ ip: connection.ip, country: connection.country, flag: connection.flag, status: 'proxied' });
});

app.get('/api/vpn/logs', authenticateToken, (req, res) => {
  const userLogs = vpnLogs.filter(log => log.userId === req.user.userId);
  res.json(userLogs);
});

// HTML UI Template for React/Vite/Netlify fallback
const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VPN & OAuth Control Center</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen p-6 font-sans">
  <div class="max-w-4xl mx-auto space-y-6">
    <header class="border-b border-slate-800 pb-4 flex justify-between items-center">
      <div>
        <h1 class="text-2xl font-bold tracking-tight">VPN & OAuth Gateway</h1>
        <p class="text-sm text-slate-400">Netlify Serverless Deployment (Port 5900 Configured)</p>
      </div>
      <div id="userInfo" class="text-sm bg-slate-800 px-3 py-1.5 rounded border border-slate-700">Not Logged In</div>
    </header>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div class="bg-slate-800 p-5 rounded-lg border border-slate-700 space-y-4">
        <h2 class="text-lg font-semibold">Device Authorization Flow</h2>
        <input id="userCodeInput" type="text" placeholder="Enter Device Code (e.g., A2B4)" class="w-full bg-slate-900 border border-slate-700 p-2 rounded text-sm uppercase">
        <button onclick="connectDevice()" class="w-full bg-indigo-600 hover:bg-indigo-500 py-2 rounded font-medium transition">Connect Account</button>
      </div>
      <div class="bg-slate-800 p-5 rounded-lg border border-slate-700 space-y-4">
        <h2 class="text-lg font-semibold">VPN Control Center</h2>
        <div id="vpnStatus" class="text-sm bg-slate-900 p-3 rounded border border-slate-700">Status: Disconnected</div>
        <select id="countrySelect" class="w-full bg-slate-900 border border-slate-700 p-2 rounded text-sm"></select>
        <div class="flex gap-2">
          <button onclick="connectVpn()" class="flex-1 bg-emerald-600 hover:bg-emerald-500 py-2 rounded font-medium transition">Connect VPN</button>
          <button onclick="disconnectVpn()" class="flex-1 bg-rose-600 hover:bg-rose-500 py-2 rounded font-medium transition">Disconnect</button>
        </div>
      </div>
    </div>
  </div>
  <script>
    async function init() {
      const token = localStorage.getItem('token');
      if (token) {
        const res = await fetch('/api/whoami', { headers: { 'Authorization': \`Bearer \${token}\` } });
        if (res.ok) {
          const data = await res.json();
          document.getElementById('userInfo').innerText = \`Logged in: \${data.email || data.user_id}\`;
        }
      }
      const countryRes = await fetch('/api/vpn/countries');
      const countries = await countryRes.json();
      document.getElementById('countrySelect').innerHTML = countries.map(c => \`<option value="\${c.code}">\${c.flag} \${c.name} (\${c.ip})</option>\`).join('');
    }
    async function connectDevice() {
      const user_code = document.getElementById('userCodeInput').value;
      const token = localStorage.getItem('token');
      const res = await fetch('/api/device/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': \`Bearer \${token}\` },
        body: JSON.stringify({ user_code })
      });
      const data = await res.json();
      alert(data.message || data.error);
    }
    async function connectVpn() {
      const country_code = document.getElementById('countrySelect').value;
      const token = localStorage.getItem('token');
      const res = await fetch('/api/vpn/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': \`Bearer \${token}\` },
        body: JSON.stringify({ country_code })
      });
      const data = await res.json();
      document.getElementById('vpnStatus').innerText = \`Connected: \${data.flag} \${data.country} (\${data.ip})\`;
    }
    async function disconnectVpn() {
      const token = localStorage.getItem('token');
      await fetch('/api/vpn/disconnect', { method: 'POST', headers: { 'Authorization': \`Bearer \${token}\` } });
      document.getElementById('vpnStatus').innerText = 'Status: Disconnected';
    }
    init();
  </script>
</body>
</html>`;

app.get('/', (req, res) => {
  res.send(htmlContent);
});

app.get('/me', (req, res) => {
  res.redirect('/');
});

app.get('/oauth/device', (req, res) => {
  res.send(htmlContent);
});

module.exports.handler = serverless(app);
