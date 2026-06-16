import httpx
import respx

from core.context import PentestContext, CaptchaType, LoginForm
from core.scope import ScopePolicy
from agents.attack_agent import run_attack


def _ctx(**kw):
    ctx = PentestContext(target_url="https://app.example.com")
    ctx.scope = ScopePolicy(authorized=True, throttle_seconds=0, max_active_requests=100)
    ctx.llm = None  # force deterministic planner
    ctx.login_form = LoginForm(
        action_url="https://app.example.com/login",
        username_field="username",
        password_field="password",
    )
    for k, v in kw.items():
        setattr(ctx, k, v)
    return ctx


@respx.mock
async def test_captcha_client_only_is_flagged_critical():
    respx.post("https://app.example.com/login").mock(
        return_value=httpx.Response(200, text="login failed")  # no 'captcha' error
    )
    ctx = _ctx(captcha_detected=True, captcha_type=CaptchaType.RECAPTCHA_V2)

    await run_attack(ctx)

    titles = {f.title for f in ctx.findings}
    assert "CAPTCHA Not Enforced Server-Side" in titles


@respx.mock
async def test_scope_budget_caps_requests():
    respx.post("https://app.example.com/login").mock(
        return_value=httpx.Response(200, text="nope")
    )
    ctx = _ctx()
    ctx.scope = ScopePolicy(authorized=True, throttle_seconds=0, max_active_requests=3)

    await run_attack(ctx)

    assert ctx.scope.requests_sent <= 3
