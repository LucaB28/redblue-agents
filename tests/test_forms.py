from core.forms import detect_login_form, _detect_with_regex

LOGIN_HTML = """
<html><body>
  <form action="/auth/login" method="POST">
    <input type="text" name="email" />
    <input type="password" name="pass" />
    <input type="hidden" name="csrf_token" value="abc123" />
    <input type="submit" value="Sign in" />
  </form>
</body></html>
"""

NO_LOGIN_HTML = "<html><body><form action='/search'><input name='q'></form></body></html>"


def test_detects_login_form_fields():
    form = detect_login_form(LOGIN_HTML, "https://app.example.com/")
    assert form is not None
    assert form.action_url == "https://app.example.com/auth/login"
    assert form.method == "post"
    assert form.username_field == "email"
    assert form.password_field == "pass"
    assert form.extra_fields.get("csrf_token") == "abc123"


def test_returns_none_without_password_input():
    assert detect_login_form(NO_LOGIN_HTML, "https://app.example.com/") is None


def test_regex_fallback_matches_bs4():
    form = _detect_with_regex(LOGIN_HTML, "https://app.example.com/")
    assert form is not None
    assert form.password_field == "pass"
    assert form.username_field == "email"
    assert form.extra_fields.get("csrf_token") == "abc123"
