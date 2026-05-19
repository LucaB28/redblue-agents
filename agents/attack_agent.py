"""
agents/attack_agent.py

Active testing phase. Reads everything Recon wrote to context
and builds its test plan accordingly — not a fixed checklist.

Key behavior: if a critical finding is confirmed, the agent
stops testing that vector and moves on. No redundant checks.

Writes to: context.auth_vectors_tested, context.captcha_enforcement,
           context.rate_limit_result, context.findings
"""

import asyncio
import httpx
from core.context import (
    PentestContext, AuthVector, CaptchaEnforcement,
    RateLimitResult, Finding, Severity, CaptchaType
)

# Placeholder credentials for auth testing against DVWA/test targets
TEST_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("test", "test"),
]


async def run_attack(ctx: PentestContext) -> PentestContext:
    if ctx.abort:
        ctx.log("attack", "Skipping — context flagged abort from recon phase.")
        return ctx

    ctx.log("attack", "Starting active testing phase.")
    ctx.log("attack", f"Reading recon memory: captcha={ctx.captcha_type.value}, stack={ctx.tech_stack}")

    # Build test plan from recon findings — this is the memory model in action
    test_plan = _build_test_plan(ctx)
    ctx.log("attack", f"Test plan: {', '.join(test_plan)}")

    async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
        if "captcha_enforcement" in test_plan:
            await _test_captcha_enforcement(ctx, client)

        if "rate_limiting" in test_plan:
            # Only test rate limiting if we know CAPTCHA is missing or client-side
            # (no point testing rate limit if auth is already broken at CAPTCHA level)
            should_test = ctx.captcha_enforcement in (
                CaptchaEnforcement.CLIENT_ONLY,
                CaptchaEnforcement.MISSING,
                CaptchaEnforcement.UNKNOWN,
            )
            if should_test:
                await _test_rate_limiting(ctx, client)
            else:
                ctx.log("attack", "Rate limit test skipped — CAPTCHA is server-enforced, reduces attack surface.")

        if "user_enumeration" in test_plan:
            await _test_user_enumeration(ctx, client)

    ctx.log("attack", f"Attack phase complete. Vectors tested: {len(ctx.auth_vectors_tested)}")
    return ctx


def _build_test_plan(ctx: PentestContext) -> list[str]:
    """
    Decides what to test based on recon findings.
    This is where the memory model creates real value.
    """
    plan = []

    # Always test CAPTCHA enforcement if one was detected
    if ctx.captcha_detected:
        plan.append("captcha_enforcement")
    else:
        ctx.log("attack", "No CAPTCHA detected by recon — skipping captcha enforcement tests.")

    # Always test rate limiting on auth endpoints
    plan.append("rate_limiting")

    # Test user enumeration if timing differences are plausible
    plan.append("user_enumeration")

    return plan


async def _test_captcha_enforcement(ctx: PentestContext, client: httpx.AsyncClient) -> None:
    """
    Core CAPTCHA test: does the server actually validate the token?
    We send a login request with the CAPTCHA field removed entirely.
    """
    ctx.log("attack", f"Testing CAPTCHA server-side enforcement (type: {ctx.captcha_type.value})")

    login_url = _resolve_login_endpoint(ctx.target_url)

    # Determine which field name to omit based on CAPTCHA type
    captcha_field = _get_captcha_field_name(ctx.captcha_type)

    # Attempt login WITHOUT the CAPTCHA token
    payload = {
        "username": "admin",
        "password": "wrongpassword_intentional",
        # captcha_field intentionally omitted
    }

    try:
        response = await client.post(login_url, data=payload)

        vector = AuthVector(
            name="CAPTCHA Enforcement — Server Side",
            description=f"POST to {login_url} with {captcha_field} field removed",
            request_summary=f"POST {login_url} | body: username=admin, password=*** (no {captcha_field})",
            response_code=response.status_code,
        )

        # Heuristic: if we don't get a CAPTCHA-specific error, enforcement is missing
        body_lower = response.text.lower()
        captcha_rejected = any(kw in body_lower for kw in [
            "captcha", "robot", "verification failed", "invalid captcha"
        ])

        if not captcha_rejected and response.status_code < 500:
            ctx.captcha_enforcement = CaptchaEnforcement.CLIENT_ONLY
            vector.finding = "Request accepted without CAPTCHA token — enforcement is client-side only"
            ctx.log("attack", "CRITICAL: CAPTCHA not validated server-side. Request processed without token.")
            ctx.add_finding(Finding(
                title="CAPTCHA Not Enforced Server-Side",
                severity=Severity.CRITICAL,
                owasp_category="A07:2021 – Identification and Authentication Failures",
                cvss_score=9.1,
                description=(
                    f"The login endpoint accepts authentication requests without a valid "
                    f"{ctx.captcha_type.value} token. The CAPTCHA control exists only in "
                    f"client-side JavaScript and provides no protection against automation."
                ),
                evidence=(
                    f"POST {login_url} with '{captcha_field}' field removed → "
                    f"HTTP {response.status_code}, no CAPTCHA error in response."
                ),
                remediation=(
                    "Validate the CAPTCHA token server-side on every authentication request "
                    "before processing credentials. Reject requests that omit or submit an "
                    "invalid token with HTTP 400."
                ),
            ))
        else:
            ctx.captcha_enforcement = CaptchaEnforcement.SERVER_SIDE
            vector.finding = None
            ctx.log("attack", "CAPTCHA appears to be enforced server-side. No bypass found via token omission.")

        ctx.auth_vectors_tested.append(vector)

    except httpx.RequestError as e:
        ctx.log("attack", f"CAPTCHA enforcement test failed: {e}")


async def _test_rate_limiting(ctx: PentestContext, client: httpx.AsyncClient) -> None:
    """
    Send N rapid requests and check for 429 or lockout behavior.
    """
    ctx.log("attack", "Testing rate limiting on authentication endpoint...")

    login_url = _resolve_login_endpoint(ctx.target_url)
    result = RateLimitResult(tested=True)
    request_count = 0
    batch_size = 20

    for i in range(batch_size):
        try:
            response = await client.post(login_url, data={
                "username": "admin",
                "password": f"brutetest_{i}",
            })
            request_count += 1

            if response.status_code == 429:
                result.block_triggered = True
                result.block_at_request = i + 1
                ctx.log("attack", f"Rate limit triggered at request #{i+1}. Good.")
                break

            if "locked" in response.text.lower() or "too many" in response.text.lower():
                result.block_triggered = True
                result.block_at_request = i + 1
                ctx.log("attack", f"Account/IP lockout detected at request #{i+1}.")
                break

            await asyncio.sleep(0.1)

        except httpx.RequestError:
            break

    result.requests_sent = request_count

    if not result.block_triggered:
        result.notes = f"No rate limiting detected after {request_count} requests"
        ctx.log("attack", f"No rate limit or lockout after {request_count} requests. Flagging.")
        ctx.add_finding(Finding(
            title="No Rate Limiting on Authentication Endpoint",
            severity=Severity.HIGH,
            owasp_category="A07:2021 – Identification and Authentication Failures",
            cvss_score=7.5,
            description="The authentication endpoint does not enforce rate limiting, enabling brute-force attacks.",
            evidence=f"{request_count} sequential failed login attempts with no 429 response or lockout.",
            remediation=(
                "Implement rate limiting (e.g., max 5 failed attempts per IP per minute). "
                "Return HTTP 429 with Retry-After header. Consider progressive delays or CAPTCHA escalation."
            ),
        ))

    ctx.rate_limit_result = result


async def _test_user_enumeration(ctx: PentestContext, client: httpx.AsyncClient) -> None:
    """
    Compare response times/messages for valid vs invalid usernames.
    A timing difference reveals whether a username exists.
    """
    ctx.log("attack", "Testing for user enumeration via response differences...")

    login_url = _resolve_login_endpoint(ctx.target_url)

    import time
    timings = {}

    for username in ["admin", "nonexistent_xz99q"]:
        start = time.monotonic()
        try:
            response = await client.post(login_url, data={
                "username": username,
                "password": "wrongpassword_timing_test",
            })
            elapsed = time.monotonic() - start
            timings[username] = {
                "time_ms": round(elapsed * 1000),
                "status": response.status_code,
                "body_length": len(response.text),
            }
        except httpx.RequestError:
            pass

    if len(timings) == 2:
        time_diff = abs(timings["admin"]["time_ms"] - timings["nonexistent_xz99q"]["time_ms"])
        body_diff = abs(timings["admin"]["body_length"] - timings["nonexistent_xz99q"]["body_length"])

        if time_diff > 300 or body_diff > 50:
            ctx.log("attack", f"Possible user enumeration: timing diff={time_diff}ms, body diff={body_diff}b")
            ctx.add_finding(Finding(
                title="Possible Username Enumeration",
                severity=Severity.MEDIUM,
                owasp_category="A07:2021 – Identification and Authentication Failures",
                cvss_score=5.3,
                description="Different response characteristics for valid vs invalid usernames may allow enumeration.",
                evidence=(
                    f"'admin': {timings['admin']['time_ms']}ms, {timings['admin']['body_length']}b | "
                    f"'nonexistent': {timings['nonexistent_xz99q']['time_ms']}ms, {timings['nonexistent_xz99q']['body_length']}b"
                ),
                remediation="Return identical responses (timing, body, status) for all failed auth attempts.",
            ))
        else:
            ctx.log("attack", f"No significant enumeration signal detected (timing diff={time_diff}ms).")


def _resolve_login_endpoint(base_url: str) -> str:
    """Best-effort login endpoint resolution. Extend with crawling for production use."""
    base = base_url.rstrip("/")
    # DVWA default
    if "8080" in base or "dvwa" in base.lower():
        return f"{base}/login.php"
    return f"{base}/login"


def _get_captcha_field_name(captcha_type: CaptchaType) -> str:
    mapping = {
        CaptchaType.RECAPTCHA_V2: "g-recaptcha-response",
        CaptchaType.RECAPTCHA_V3: "g-recaptcha-response",
        CaptchaType.HCAPTCHA: "h-captcha-response",
        CaptchaType.CUSTOM: "captcha",
        CaptchaType.NONE: "captcha",
    }
    return mapping.get(captcha_type, "captcha")
