import httpx
import respx

from core.context import PentestContext, LoginForm
from core.scope import ScopePolicy
from agents.auth_agent import run_auth


def _ctx():
    ctx = PentestContext(target_url="https://app.example.com")
    ctx.scope = ScopePolicy(authorized=True, throttle_seconds=0, max_active_requests=50)
    ctx.username = "alice"
    ctx.password = "secret"
    ctx.login_form = LoginForm(
        action_url="https://app.example.com/login",
        username_field="username",
        password_field="password",
    )
    return ctx


@respx.mock
async def test_session_fixation_flagged_when_id_unchanged():
    # Same session cookie before and after login → fixation.
    respx.get("https://app.example.com").mock(
        return_value=httpx.Response(200, headers=[("Set-Cookie", "sessionid=FIXED; Path=/")], text="home")
    )
    respx.post("https://app.example.com/login").mock(
        return_value=httpx.Response(
            200,
            headers=[("Set-Cookie", "sessionid=FIXED; Path=/")],
            text="Welcome, click logout to exit",
        )
    )
    ctx = _ctx()
    await run_auth(ctx)

    assert ctx.authenticated is True
    titles = {f.title for f in ctx.findings}
    assert "Session ID Not Regenerated After Login (Session Fixation)" in titles


@respx.mock
async def test_failed_login_marks_not_authenticated():
    respx.get("https://app.example.com").mock(return_value=httpx.Response(200, text="home"))
    respx.post("https://app.example.com/login").mock(
        return_value=httpx.Response(200, text="Invalid credentials, try again")
    )
    ctx = _ctx()
    await run_auth(ctx)

    assert ctx.authenticated is False
    assert any(f.title == "Authenticated Scan Could Not Log In" for f in ctx.findings)


async def test_auth_skipped_without_credentials():
    ctx = _ctx()
    ctx.username = None
    ctx.password = None
    await run_auth(ctx)
    assert ctx.authenticated is None
    assert ctx.findings == []
