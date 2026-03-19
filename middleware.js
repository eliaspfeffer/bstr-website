/**
 * Vercel Edge Middleware — Password Protection
 *
 * Env vars to set in Vercel dashboard:
 *   COOKIE_SECRET   — random secret used to sign session cookies (one value, shared)
 *   CREDENTIALS     — comma-separated user:pass pairs, e.g.:
 *                     bstr:mypassword,alice:anotherpass,bob:thirdpass
 *
 * To add a new user: append ",newuser:newpass" to CREDENTIALS in Vercel → Settings → Environment Variables.
 * No redeployment needed — env var changes take effect on next request.
 */

export const config = {
  matcher: '/(.*)',
  runtime: 'edge',
}

function parseCredentials() {
  const raw = process.env.CREDENTIALS || ''
  const map = {}
  for (const pair of raw.split(',')) {
    const colon = pair.indexOf(':')
    if (colon > 0) {
      const user = pair.slice(0, colon).trim()
      const pass = pair.slice(colon + 1).trim()
      if (user) map[user] = pass
    }
  }
  return map
}

function loginPage(error = '') {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Login — BSTR Research</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #0a0a0a;
      color: #f0f0f0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .card {
      background: #141414;
      border: 1px solid #242424;
      border-radius: 14px;
      padding: 44px 40px;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.5);
    }
    .logo {
      font-size: 1.6rem;
      font-weight: 700;
      color: #f7931a;
      letter-spacing: -0.5px;
      margin-bottom: 6px;
    }
    .subtitle {
      font-size: 0.83rem;
      color: #666;
      margin-bottom: 32px;
    }
    label {
      display: block;
      font-size: 0.78rem;
      font-weight: 500;
      color: #999;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 7px;
    }
    input {
      width: 100%;
      background: #0d0d0d;
      border: 1px solid #2e2e2e;
      border-radius: 8px;
      color: #fff;
      font-size: 0.95rem;
      padding: 11px 14px;
      margin-bottom: 18px;
      outline: none;
      transition: border-color 0.15s;
    }
    input:focus { border-color: #f7931a; }
    button {
      width: 100%;
      background: #f7931a;
      border: none;
      border-radius: 8px;
      color: #000;
      font-size: 0.95rem;
      font-weight: 700;
      padding: 13px;
      cursor: pointer;
      transition: opacity 0.15s;
      margin-top: 4px;
    }
    button:hover { opacity: 0.88; }
    .error {
      background: rgba(220,53,53,0.12);
      border: 1px solid rgba(220,53,53,0.35);
      border-radius: 8px;
      color: #f08080;
      font-size: 0.85rem;
      padding: 10px 14px;
      margin-bottom: 20px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">BSTR</div>
    <div class="subtitle">Private access — please log in to continue.</div>
    ${error ? `<div class="error">${error}</div>` : ''}
    <form method="POST" action="/__login">
      <label>Username</label>
      <input type="text" name="username" autocomplete="username" autofocus required />
      <label>Password</label>
      <input type="password" name="password" autocomplete="current-password" required />
      <button type="submit">Continue →</button>
    </form>
  </div>
</body>
</html>`
}

function getAuthCookie(request) {
  const header = request.headers.get('cookie') || ''
  for (const part of header.split(';')) {
    const c = part.trim()
    if (c.startsWith('bstr_auth=')) return c.slice('bstr_auth='.length)
  }
  return null
}

export default async function middleware(request) {
  const url = new URL(request.url)
  const cookieSecret = process.env.COOKIE_SECRET || ''

  // ── Handle login form POST ────────────────────────────────────────────────
  if (request.method === 'POST' && url.pathname === '/__login') {
    let body = ''
    try { body = await request.text() } catch (_) {}
    const params = new URLSearchParams(body)
    const username = (params.get('username') || '').trim()
    const password = params.get('password') || ''

    const creds = parseCredentials()

    if (username && creds[username] !== undefined && creds[username] === password) {
      // Valid — set cookie and redirect to home
      return new Response(null, {
        status: 302,
        headers: {
          Location: '/',
          'Set-Cookie': [
            `bstr_auth=${cookieSecret}`,
            'HttpOnly',
            'Secure',
            'SameSite=Strict',
            'Path=/',
            'Max-Age=604800', // 7 days
          ].join('; '),
        },
      })
    }

    // Invalid credentials
    return new Response(loginPage('Invalid username or password.'), {
      status: 401,
      headers: { 'Content-Type': 'text/html' },
    })
  }

  // ── Check session cookie ──────────────────────────────────────────────────
  const token = getAuthCookie(request)
  if (cookieSecret && token === cookieSecret) {
    return // authenticated — pass through to static file
  }

  // ── Not authenticated — show login page ───────────────────────────────────
  return new Response(loginPage(), {
    status: 200,
    headers: { 'Content-Type': 'text/html' },
  })
}
