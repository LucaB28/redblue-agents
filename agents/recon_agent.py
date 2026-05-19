"""
agents/recon_agent.py

Passive reconnaissance. Analyzes headers, detects tech stack,
identifies CAPTCHA type, evaluates cookie security flags.
No authentication attempts — pure observation.

Writes to: context.tech_stack, context.security_headers,
           context.captcha_detected, context.captcha_type,
           context.cookies_analyzed, context.cors_policy
"""

import httpx
from core.context import (
    PentestContext, HeaderAnalysis, CaptchaType, Finding, Severity
)


SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]

CAPTCHA_SIGNALS = {
    CaptchaType.RECAPTCHA_V2: [
        "google.com/recaptcha",
        "g-recaptcha",
        "recaptcha/api.js",
    ],
    CaptchaType.RECAPTCHA_V3: [
        "recaptcha/api.js?render=",
        "grecaptcha.execute",
    ],
    CaptchaType.HCAPTCHA: [
        "hcaptcha.com",
        "h-captcha",
    ],
}

TECH_SIGNALS = {
    "WordPress": ["wp-content", "wp-json", "WordPress"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "Django": ["csrftoken", "django"],
    "ASP.NET": ["__RequestVerificationToken", "ASP.NET"],
    "Next.js": ["__NEXT_DATA__", "_next/"],
    "React": ["react", "__reactFiber"],
    "nginx": ["nginx"],
    "Apache": ["Apache"],
}


async def run_recon(ctx: PentestContext) -> PentestContext:
    ctx.log("recon", f"Starting passive reconnaissance on {ctx.target_url}")

    async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
        try:
            response = await client.get(ctx.target_url)
        except httpx.RequestError as e:
            ctx.log("recon", f"Connection error: {e}. Aborting.")
            ctx.abort = True
            ctx.abort_reason = str(e)
            return ctx

        ctx.log("recon", f"Response: HTTP {response.status_code}")

        _analyze_headers(ctx, response)
        _analyze_tech_stack(ctx, response)
        _analyze_captcha(ctx, response)
        _analyze_cookies(ctx, response)
        _analyze_cors(ctx, response)

    ctx.log("recon", f"Recon complete. Tech stack: {ctx.tech_stack or ['unknown']}")
    ctx.log("recon", f"CAPTCHA detected: {ctx.captcha_detected} ({ctx.captcha_type.value})")
    return ctx


def _analyze_headers(ctx: PentestContext, response: httpx.Response) -> None:
    ctx.log("recon", "Analyzing security headers...")
    missing = []

    for header in SECURITY_HEADERS:
        present = header.lower() in {k.lower() for k in response.headers}
        value = response.headers.get(header)
        risk = None if present else f"Missing {header} — consider adding"

        ctx.security_headers[header] = HeaderAnalysis(
            name=header,
            present=present,
            value=value,
            risk_note=risk,
        )
        if not present:
            missing.append(header)

    if missing:
        ctx.log("recon", f"Missing security headers: {', '.join(missing)}")
        if "Content-Security-Policy" in missing and "X-Frame-Options" in missing:
            ctx.add_finding(Finding(
                title="Multiple Security Headers Missing",
                severity=Severity.MEDIUM,
                owasp_category="A05:2021 – Security Misconfiguration",
                cvss_score=5.3,
                description="Critical security headers are absent from HTTP responses.",
                evidence=f"Missing: {', '.join(missing)}",
                remediation=(
                    "Add security headers at the web server or application layer. "
                    "Minimum: CSP, X-Frame-Options, X-Content-Type-Options, HSTS."
                ),
            ))


def _analyze_tech_stack(ctx: PentestContext, response: httpx.Response) -> None:
    body = response.text
    headers_str = str(response.headers)
    combined = body + headers_str

    for tech, signals in TECH_SIGNALS.items():
        if any(s.lower() in combined.lower() for s in signals):
            ctx.tech_stack.append(tech)

    server = response.headers.get("Server", "")
    if server and server not in ctx.tech_stack:
        ctx.tech_stack.append(f"Server:{server}")

    x_powered = response.headers.get("X-Powered-By", "")
    if x_powered:
        ctx.tech_stack.append(f"PoweredBy:{x_powered}")
        ctx.add_finding(Finding(
            title="Technology Disclosure via X-Powered-By Header",
            severity=Severity.LOW,
            owasp_category="A05:2021 – Security Misconfiguration",
            cvss_score=3.1,
            description="Server discloses backend technology in response headers.",
            evidence=f"X-Powered-By: {x_powered}",
            remediation="Remove or obfuscate X-Powered-By and Server headers.",
        ))


def _analyze_captcha(ctx: PentestContext, response: httpx.Response) -> None:
    body = response.text

    for captcha_type, signals in CAPTCHA_SIGNALS.items():
        if any(s.lower() in body.lower() for s in signals):
            ctx.captcha_detected = True
            ctx.captcha_type = captcha_type
            ctx.log("recon", f"CAPTCHA identified: {captcha_type.value}")
            return

    ctx.log("recon", "No CAPTCHA detected on login page.")


def _analyze_cookies(ctx: PentestContext, response: httpx.Response) -> None:
    issues = []
    for cookie in response.cookies.jar:
        flags = {
            "httponly": cookie.has_nonstandard_attr("HttpOnly") or getattr(cookie, "_rest", {}).get("HttpOnly") is not None,
            "secure": bool(cookie.secure),
            "samesite": cookie.get_nonstandard_attr("SameSite"),
        }
        ctx.cookies_analyzed[cookie.name] = flags

        if not flags["httponly"]:
            issues.append(f"{cookie.name}: missing HttpOnly")
        if not flags["secure"]:
            issues.append(f"{cookie.name}: missing Secure flag")

    if issues:
        ctx.log("recon", f"Cookie flag issues: {'; '.join(issues)}")


def _analyze_cors(ctx: PentestContext, response: httpx.Response) -> None:
    acao = response.headers.get("Access-Control-Allow-Origin")
    if acao:
        ctx.cors_policy = acao
        if acao == "*":
            ctx.log("recon", "CORS wildcard detected — flagging for attack agent.")
            ctx.add_finding(Finding(
                title="Permissive CORS Policy",
                severity=Severity.MEDIUM,
                owasp_category="A05:2021 – Security Misconfiguration",
                cvss_score=5.4,
                description="Server allows cross-origin requests from any domain.",
                evidence="Access-Control-Allow-Origin: *",
                remediation="Restrict CORS to known trusted origins. Never use wildcard on authenticated endpoints.",
            ))
