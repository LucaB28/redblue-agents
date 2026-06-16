"""
core/forms.py

Login-form discovery. This is what lets the tool point at *any* site's
login page instead of a hardcoded /login path: it parses the returned HTML,
finds the form that contains a password input, and extracts the real action
URL and field names (including hidden CSRF tokens).

Uses BeautifulSoup when available; falls back to a regex parser so the tool
still works if bs4 isn't installed.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urljoin

from core.context import LoginForm

_CAPTCHA_FIELDS = {"g-recaptcha-response", "h-captcha-response", "captcha", "captcha_code"}
_USERNAME_HINTS = ("user", "email", "login", "account", "name")


def detect_login_form(html: str, page_url: str) -> Optional[LoginForm]:
    """Return the most likely login form on the page, or None."""
    try:
        return _detect_with_bs4(html, page_url)
    except ImportError:
        return _detect_with_regex(html, page_url)


def _detect_with_bs4(html: str, page_url: str) -> Optional[LoginForm]:
    from bs4 import BeautifulSoup  # raises ImportError -> regex fallback

    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        pwd = form.find("input", attrs={"type": "password"})
        if not pwd:
            continue

        action = form.get("action") or page_url
        method = (form.get("method") or "post").lower()
        password_field = pwd.get("name") or "password"

        username_field = "username"
        extra: dict[str, str] = {}
        captcha_field = None

        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name or inp is pwd:
                continue
            itype = (inp.get("type") or "text").lower()
            if name in _CAPTCHA_FIELDS:
                captcha_field = name
            elif itype in ("text", "email") and _looks_like_username(name):
                username_field = name
            elif itype == "hidden":
                extra[name] = inp.get("value") or ""

        return LoginForm(
            action_url=urljoin(page_url, action),
            method=method,
            username_field=username_field,
            password_field=password_field,
            captcha_field=captcha_field,
            extra_fields=extra,
        )
    return None


def _detect_with_regex(html: str, page_url: str) -> Optional[LoginForm]:
    for form_html in re.findall(r"<form\b[^>]*>.*?</form>", html, re.IGNORECASE | re.DOTALL):
        if not re.search(r'type=["\']password["\']', form_html, re.IGNORECASE):
            continue

        action_m = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method_m = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        action = action_m.group(1) if action_m else page_url
        method = (method_m.group(1) if method_m else "post").lower()

        inputs = re.findall(r"<input\b[^>]*>", form_html, re.IGNORECASE)
        password_field = "password"
        username_field = "username"
        captcha_field = None
        extra: dict[str, str] = {}

        for inp in inputs:
            name_m = re.search(r'name=["\']([^"\']*)["\']', inp, re.IGNORECASE)
            type_m = re.search(r'type=["\']([^"\']*)["\']', inp, re.IGNORECASE)
            if not name_m:
                continue
            name = name_m.group(1)
            itype = (type_m.group(1) if type_m else "text").lower()
            if itype == "password":
                password_field = name
            elif name in _CAPTCHA_FIELDS:
                captcha_field = name
            elif itype in ("text", "email") and _looks_like_username(name):
                username_field = name
            elif itype == "hidden":
                val_m = re.search(r'value=["\']([^"\']*)["\']', inp, re.IGNORECASE)
                extra[name] = val_m.group(1) if val_m else ""

        return LoginForm(
            action_url=urljoin(page_url, action),
            method=method,
            username_field=username_field,
            password_field=password_field,
            captcha_field=captcha_field,
            extra_fields=extra,
        )
    return None


def _looks_like_username(name: str) -> bool:
    return any(h in name.lower() for h in _USERNAME_HINTS)
