// FollowerPilot OAuth broker.
// Run this as the operator-controlled HTTPS service. It is the only component
// that knows the Meta/Instagram client secret; desktop clients receive one-use
// tickets and never receive the developer secret.
'use strict';

const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 43100);
const PUBLIC_URL = (process.env.FOLLOWERPILOT_AUTH_PUBLIC_URL || `http://127.0.0.1:${PORT}`).replace(/\/$/, '');
const CLIENT_ID = process.env.INSTAGRAM_CLIENT_ID;
const CLIENT_SECRET = process.env.INSTAGRAM_CLIENT_SECRET;
const API_VERSION = process.env.INSTAGRAM_API_VERSION || 'v22.0';
const SCOPES = process.env.INSTAGRAM_SCOPES || 'instagram_business_basic';
const APP_REDIRECT_PREFIX = 'followerpilot://oauth/callback';
const AUTHORIZE_URL = 'https://www.instagram.com/oauth/authorize';
const TOKEN_URL = 'https://api.instagram.com/oauth/access_token';
const sessions = new Map();
const tickets = new Map();

function json(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(body);
}

function fail(res, status, message) { json(res, status, { error: message }); }
function randomId(bytes = 32) { return crypto.randomBytes(bytes).toString('hex'); }
function configured() { return Boolean(CLIENT_ID && CLIENT_SECRET); }
function isValidAppRedirect(value) { return typeof value === 'string' && value.startsWith(APP_REDIRECT_PREFIX); }
function cleanup() {
  const now = Date.now();
  for (const [key, value] of sessions) if (value.expiresAt <= now) sessions.delete(key);
  for (const [key, value] of tickets) if (value.expiresAt <= now) tickets.delete(key);
}

async function exchangeCode(code) {
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    grant_type: 'authorization_code',
    redirect_uri: `${PUBLIC_URL}/oauth/callback`,
    code,
  });
  const response = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  const data = await response.json();
  if (!response.ok || !data.access_token) {
    throw new Error(data.error_message || data.error_type || `Instagram token exchange failed (${response.status})`);
  }

  const profileResponse = await fetch(
    `https://graph.instagram.com/${API_VERSION}/me?fields=user_id,username,account_type&access_token=${encodeURIComponent(data.access_token)}`,
  );
  const profile = await profileResponse.json();
  if (!profileResponse.ok || profile.error) {
    throw new Error(profile.error?.message || `Instagram profile lookup failed (${profileResponse.status})`);
  }

  return {
    accessToken: data.access_token,
    expiresAt: data.expires_in ? Date.now() + Number(data.expires_in) * 1000 : 0,
    profile: {
      id: profile.user_id || profile.id,
      username: profile.username,
      accountType: profile.account_type,
    },
  };
}

async function handleAuthorize(req, res, url) {
  if (!configured()) return fail(res, 503, 'The FollowerPilot OAuth service is not configured by its operator.');
  const nonce = url.searchParams.get('nonce');
  const appRedirect = url.searchParams.get('redirect_uri');
  if (!nonce || nonce.length < 32 || !isValidAppRedirect(appRedirect)) {
    return fail(res, 400, 'Invalid FollowerPilot login request.');
  }

  const state = randomId(24);
  sessions.set(state, { nonce, appRedirect, expiresAt: Date.now() + 10 * 60 * 1000 });
  const authorize = new URL(AUTHORIZE_URL);
  authorize.searchParams.set('client_id', CLIENT_ID);
  authorize.searchParams.set('redirect_uri', `${PUBLIC_URL}/oauth/callback`);
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('scope', SCOPES);
  authorize.searchParams.set('state', state);
  res.writeHead(302, { location: authorize.toString(), 'cache-control': 'no-store' });
  res.end();
}

async function handleCallback(req, res, url) {
  const state = url.searchParams.get('state');
  const session = state && sessions.get(state);
  if (!session || session.expiresAt <= Date.now()) return fail(res, 400, 'Instagram login expired. Please try again.');
  sessions.delete(state);

  const error = url.searchParams.get('error_description') || url.searchParams.get('error');
  if (error) {
    const destination = new URL(session.appRedirect);
    destination.searchParams.set('error', error);
    res.writeHead(302, { location: destination.toString(), 'cache-control': 'no-store' });
    return res.end();
  }

  const code = url.searchParams.get('code');
  if (!code) return fail(res, 400, 'Instagram did not return an authorization code.');
  try {
    const auth = await exchangeCode(code);
    const ticket = randomId(32);
    tickets.set(ticket, { nonce: session.nonce, auth, expiresAt: Date.now() + 90 * 1000 });
    const destination = new URL(session.appRedirect);
    destination.searchParams.set('ticket', ticket);
    destination.searchParams.set('nonce', session.nonce);
    res.writeHead(302, { location: destination.toString(), 'cache-control': 'no-store' });
    res.end();
  } catch (error) {
    const destination = new URL(session.appRedirect);
    destination.searchParams.set('error', error.message);
    res.writeHead(302, { location: destination.toString(), 'cache-control': 'no-store' });
    res.end();
  }
}

async function handleTicket(req, res) {
  if (req.method !== 'POST') return fail(res, 405, 'Use POST.');
  let raw = '';
  for await (const chunk of req) raw += chunk;
  let body;
  try { body = JSON.parse(raw || '{}'); } catch { return fail(res, 400, 'Invalid JSON.'); }
  const ticket = tickets.get(body.ticket);
  const suppliedNonce = Buffer.from(String(body.nonce || ''));
  const expectedNonce = Buffer.from(String(ticket?.nonce || ''));
  if (!ticket || ticket.expiresAt <= Date.now() || suppliedNonce.length !== expectedNonce.length || !crypto.timingSafeEqual(expectedNonce, suppliedNonce)) {
    return fail(res, 401, 'Invalid or expired login ticket.');
  }
  tickets.delete(body.ticket);
  return json(res, 200, ticket.auth);
}

const server = http.createServer(async (req, res) => {
  cleanup();
  const url = new URL(req.url, PUBLIC_URL);
  try {
    if (req.method === 'GET' && url.pathname === '/health') return json(res, 200, { ok: true, configured: configured() });
    if (req.method === 'GET' && url.pathname === '/authorize') return handleAuthorize(req, res, url);
    if (req.method === 'GET' && url.pathname === '/oauth/callback') return handleCallback(req, res, url);
    if (url.pathname === '/token') return handleTicket(req, res);
    return fail(res, 404, 'Not found.');
  } catch (error) {
    return fail(res, 500, error.message || 'OAuth broker error.');
  }
});

if (require.main === module) {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`FollowerPilot OAuth broker listening on ${PUBLIC_URL}`);
    if (!configured()) console.warn('Missing INSTAGRAM_CLIENT_ID or INSTAGRAM_CLIENT_SECRET.');
  });
}

module.exports = { server, configured, isValidAppRedirect, APP_REDIRECT_PREFIX };
