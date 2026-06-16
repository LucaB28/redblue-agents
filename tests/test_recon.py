import httpx
import respx

from core.context import PentestContext, CaptchaType
from agents.recon_agent import run_recon

PAGE = """
<html><body>
  <script src="https://www.google.com/recaptcha/api.js"></script>
  <form action="/login" method="post">
    <input type="text" name="username">
    <input type="password" name="password">
  </form>
</body></html>
"""


def _make_response():
    return httpx.Response(
        200,
        headers=[
            ("Content-Type", "text/html"),
            ("X-Powered-By", "PHP/8.1"),
            ("Set-Cookie", "session=abc; Path=/"),  # no HttpOnly/Secure/SameSite
        ],
        text=PAGE,
    )


@respx.mock
async def test_recon_detects_issues_and_login_form():
    respx.get("https://app.example.com").mock(return_value=_make_response())
    ctx = PentestContext(target_url="https://app.example.com")

    await run_recon(ctx)

    titles = {f.title for f in ctx.findings}
    assert "Insecure Session Cookie Attributes" in titles
    assert "Technology Disclosure via X-Powered-By Header" in titles
    assert "Multiple Security Headers Missing" in titles

    assert ctx.captcha_detected is True
    assert ctx.captcha_type == CaptchaType.RECAPTCHA_V2

    assert ctx.login_form is not None
    assert ctx.login_form.action_url == "https://app.example.com/login"
    assert ctx.login_form.password_field == "password"

    assert ctx.cookies_analyzed["session"]["httponly"] is False
    assert ctx.cookies_analyzed["session"]["secure"] is False


@respx.mock
async def test_recon_aborts_on_connection_error():
    respx.get("https://down.example.com").mock(side_effect=httpx.ConnectError("refused"))
    ctx = PentestContext(target_url="https://down.example.com")

    await run_recon(ctx)

    assert ctx.abort is True
    assert ctx.abort_reason
