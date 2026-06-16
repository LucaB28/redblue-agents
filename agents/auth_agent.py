"""
agents/auth_agent.py

Authenticated scan. Only runs when the operator supplies --username/--password.

It performs a REAL login with the given credentials (which the operator owns),
then inspects what a logged-in session looks like:

  - Did login succeed? (so the rest of the checks are meaningful)
  - Session fixation: did the session ID change after login? If not, an attacker
    who fixes a victim's session ID before login can hijack it afterwards.
  - Session cookie hygiene: HttpOnly / Secure / SameSite on the real session.
  - Header hygiene on an authenticated page (not just the public landing page).

All requests go through ctx.scope (authorization, host allowlist, throttle,
budget). This is not credential brute-forcing — it's a single authorized login.
"""

import httpx

from core.context import PentestContext, Finding, Severity

_SESSION_HINTS = ("session", "sess", "auth", "token", "sid")
_FAIL_HINTS = ("invalid", "incorrect", "failed", "wrong", "try again", "denied")
_LOGGED_IN_HINTS = ("logout", "log out", "sign out", "signout", "my account", "dashboard")


async def run_auth(ctx: PentestContext) -> PentestContext:
    if ctx.abort:
        return ctx
    if not (ctx.username and ctx.password):
        return ctx  # no creds → authenticated scan skipped silently
    if ctx.login_form is None:
        ctx.log("auth", "Credentials supplied but no login form was found — skipping authenticated scan.")
        return ctx

    form = ctx.login_form
    ctx.log("auth", f"Attempting authenticated login as '{ctx.username}' at {form.action_url}")

    # Use a cookie-persisting client so we hold the session like a browser would.
    async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
        # 1. Capture pre-login session id (visit landing page to get an anon cookie).
        try:
            ctx.scope.before_active_request()
            await client.get(ctx.target_url)
        except httpx.RequestError as e:
            ctx.log("auth", f"Pre-login request failed: {e}. Skipping.")
            return ctx
        pre_session = _session_value(client)

        # 2. Submit real credentials.
        payload = dict(form.extra_fields)
        payload[form.username_field] = ctx.username
        payload[form.password_field] = ctx.password
        try:
            ctx.scope.assert_in_scope(form.action_url, ctx.target_url)
            ctx.scope.before_active_request()
            if form.method == "get":
                resp = await client.get(form.action_url, params=payload)
            else:
                resp = await client.post(form.action_url, data=payload)
        except httpx.RequestError as e:
            ctx.log("auth", f"Login request failed: {e}. Skipping.")
            return ctx
        except Exception as e:  # ScopeError
            ctx.log("auth", f"Authenticated scan stopped by scope policy: {e}")
            return ctx

        post_session = _session_value(client)
        ctx.authenticated = _looks_logged_in(resp, form.action_url)

        if not ctx.authenticated:
            ctx.log("auth", "Login did not appear to succeed (check credentials / login URL).")
            ctx.add_finding(Finding(
                title="Authenticated Scan Could Not Log In",
                severity=Severity.INFO,
                owasp_category="N/A",
                cvss_score=0.0,
                description="The supplied credentials did not produce a logged-in session, so authenticated checks were skipped.",
                evidence=f"POST {form.action_url} → HTTP {resp.status_code}; no logged-in signal detected.",
                remediation="Verify the username/password and that --login-url points at the real form.",
            ))
            return ctx

        ctx.log("auth", "Login succeeded. Running authenticated checks.")
        _check_session_fixation(ctx, pre_session, post_session)
        _check_session_cookie_flags(ctx, client)
        _check_authenticated_headers(ctx, resp)

    return ctx


def _session_value(client: httpx.AsyncClient):
    for name, value in client.cookies.items():
        if any(h in name.lower() for h in _SESSION_HINTS):
            return (name, value)
    return None


def _looks_logged_in(resp: httpx.Response, login_url: str) -> bool:
    body = resp.text.lower()
    if any(h in body for h in _FAIL_HINTS):
        return False
    if any(h in body for h in _LOGGED_IN_HINTS):
        return True
    # Redirected away from the login page and no failure text → likely logged in.
    return str(resp.url).rstrip("/") != login_url.rstrip("/") and resp.status_code < 400


def _check_session_fixation(ctx: PentestContext, pre, post) -> None:
    if pre and post and pre[0] == post[0] and pre[1] == post[1]:
        ctx.add_finding(Finding(
            title="Session ID Not Regenerated After Login (Session Fixation)",
            severity=Severity.HIGH,
            owasp_category="A07:2021 – Identification and Authentication Failures",
            cvss_score=7.1,
            description="The session identifier stays the same before and after authentication, enabling session-fixation attacks.",
            evidence=f"Session cookie '{pre[0]}' kept the same value across login.",
            remediation="Issue a fresh session ID on every successful login (and on privilege change).",
        ))
    else:
        ctx.log("auth", "Session ID changed after login (good — no fixation).")


def _check_session_cookie_flags(ctx: PentestContext, client: httpx.AsyncClient) -> None:
    sess = _session_value(client)
    if not sess:
        return
    name = sess[0]
    # The raw flags were captured by recon in cookies_analyzed; re-flag for the
    # authenticated session specifically since it's the high-value cookie.
    flags = ctx.cookies_analyzed.get(name, {})
    missing = [k for k in ("httponly", "secure", "samesite") if not flags.get(k)]
    if missing:
        ctx.add_finding(Finding(
            title="Authenticated Session Cookie Missing Security Flags",
            severity=Severity.HIGH,
            owasp_category="A05:2021 – Security Misconfiguration",
            cvss_score=6.5,
            description="The live session cookie is missing one or more protective attributes.",
            evidence=f"Cookie '{name}' missing: {', '.join(missing)}.",
            remediation="Set HttpOnly, Secure and SameSite=Lax/Strict on the session cookie.",
        ))


def _check_authenticated_headers(ctx: PentestContext, resp: httpx.Response) -> None:
    if "cache-control" not in {k.lower() for k in resp.headers}:
        ctx.add_finding(Finding(
            title="Authenticated Page Missing Cache-Control",
            severity=Severity.LOW,
            owasp_category="A05:2021 – Security Misconfiguration",
            cvss_score=3.1,
            description="Authenticated responses lack Cache-Control, so sensitive pages may be cached by browsers or proxies.",
            evidence="No Cache-Control header on the post-login response.",
            remediation="Send 'Cache-Control: no-store' on authenticated pages.",
        ))
