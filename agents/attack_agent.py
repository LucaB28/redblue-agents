"""
agents/attack_agent.py

Active testing phase. Reads everything Recon wrote to context and builds its
test plan accordingly — not a fixed checklist.

Two layers of decision-making:
  1. Claude (when ANTHROPIC_API_KEY is set) reasons over the recon findings and
     proposes the test plan + a rationale. This is the "reasoning" the README
     advertises.
  2. A deterministic heuristic planner runs as fallback when no key is present,
     so the tool always works offline.

Every active request goes through ctx.scope (authorization, host allowlist,
throttle, request budget). Detection logic stays deterministic — we never let
the model invent a CVSS score or a vulnerability that wasn't observed.

Writes to: context.auth_vectors_tested, context.captcha_enforcement,
           context.rate_limit_result, context.findings
"""

import time

import httpx

from core.context import (
    PentestContext, AuthVector, CaptchaEnforcement,
    RateLimitResult, Finding, Severity, CaptchaType, LoginForm,
)

VALID_PLAN_STEPS = {"captcha_enforcement", "rate_limiting", "user_enumeration"}


async def run_attack(ctx: PentestContext) -> PentestContext:
    if ctx.abort:
        ctx.log("attack", "Skipping — context flagged abort from recon phase.")
        return ctx

    ctx.log("attack", "Starting active testing phase.")
    ctx.log("attack", f"Reading recon memory: captcha={ctx.captcha_type.value}, stack={ctx.tech_stack}")

    test_plan = _plan_with_llm(ctx) or _build_test_plan(ctx)
    ctx.log("attack", f"Test plan: {', '.join(test_plan)}")

    async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
        if "captcha_enforcement" in test_plan and ctx.captcha_detected:
            await _test_captcha_enforcement(ctx, client)

        if "rate_limiting" in test_plan:
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


# --------------------------------------------------------------------------- #
# Planning
# --------------------------------------------------------------------------- #

def _plan_with_llm(ctx: PentestContext) -> list[str] | None:
    """Ask Claude to choose the test plan from recon evidence. None if no LLM."""
    llm = ctx.llm
    if llm is None or not getattr(llm, "enabled", False):
        return None

    system = (
        "You are the red-team planning module of an authorized web-app security "
        "scanner. Given reconnaissance results, decide which auth tests to run. "
        "You may ONLY pick from this exact set: "
        '["captcha_enforcement", "rate_limiting", "user_enumeration"]. '
        "Skip captcha_enforcement if no CAPTCHA was detected. "
        'Return JSON: {"plan": [...], "rationale": "one sentence"}.'
    )
    prompt = (
        f"Target: {ctx.target_url}\n"
        f"Tech stack: {ctx.tech_stack or 'unknown'}\n"
        f"CAPTCHA detected: {ctx.captcha_detected} ({ctx.captcha_type.value})\n"
        f"Login form found: {bool(ctx.login_form)}\n"
        f"Findings so far: {[f.title for f in ctx.findings]}\n"
    )
    data = llm.complete_json(system, prompt)
    if not isinstance(data, dict):
        return None

    plan = [s for s in data.get("plan", []) if s in VALID_PLAN_STEPS]
    if not plan:
        return None

    rationale = str(data.get("rationale", "")).strip()
    if rationale:
        ctx.log("attack", f"Claude plan rationale: {rationale}")
        ctx.llm_notes.append(f"Attack plan ({', '.join(plan)}): {rationale}")
    return plan


def _build_test_plan(ctx: PentestContext) -> list[str]:
    """Deterministic fallback planner."""
    plan = []
    if ctx.captcha_detected:
        plan.append("captcha_enforcement")
    else:
        ctx.log("attack", "No CAPTCHA detected by recon — skipping captcha enforcement tests.")
    plan.append("rate_limiting")
    plan.append("user_enumeration")
    return plan


# --------------------------------------------------------------------------- #
# Endpoint / field resolution (driven by recon's login-form discovery)
# --------------------------------------------------------------------------- #

def _login(ctx: PentestContext) -> LoginForm:
    """Login form discovered by recon, or a best-effort fallback."""
    if ctx.login_form is not None:
        return ctx.login_form
    base = ctx.target_url.rstrip("/")
    action = f"{base}/login.php" if ("8080" in base or "dvwa" in base.lower()) else f"{base}/login"
    return LoginForm(action_url=action)


def _build_payload(form: LoginForm, username: str, password: str) -> dict:
    payload = dict(form.extra_fields)  # carry CSRF / hidden tokens
    payload[form.username_field] = username
    payload[form.password_field] = password
    return payload


async def _send(ctx: PentestContext, client: httpx.AsyncClient, form: LoginForm, payload: dict):
    """Scope-guarded active request. Raises ScopeError if budget/host violated."""
    ctx.scope.assert_in_scope(form.action_url, ctx.target_url)
    ctx.scope.before_active_request()
    if form.method == "get":
        return await client.get(form.action_url, params=payload)
    return await client.post(form.action_url, data=payload)


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #

async def _test_captcha_enforcement(ctx: PentestContext, client: httpx.AsyncClient) -> None:
    ctx.log("attack", f"Testing CAPTCHA server-side enforcement (type: {ctx.captcha_type.value})")
    form = _login(ctx)
    captcha_field = form.captcha_field or _get_captcha_field_name(ctx.captcha_type)

    # Login WITHOUT the CAPTCHA token (omit the captcha field entirely).
    payload = _build_payload(form, "admin", "wrongpassword_intentional")
    payload.pop(captcha_field, None)

    try:
        response = await _send(ctx, client, form, payload)
    except httpx.RequestError as e:
        ctx.log("attack", f"CAPTCHA enforcement test failed: {e}")
        return

    vector = AuthVector(
        name="CAPTCHA Enforcement — Server Side",
        description=f"{form.method.upper()} to {form.action_url} with {captcha_field} removed",
        request_summary=f"{form.method.upper()} {form.action_url} | no {captcha_field}",
        response_code=response.status_code,
    )

    body_lower = response.text.lower()
    captcha_rejected = any(kw in body_lower for kw in (
        "captcha", "robot", "verification failed", "invalid captcha"
    ))

    if not captcha_rejected and response.status_code < 500:
        ctx.captcha_enforcement = CaptchaEnforcement.CLIENT_ONLY
        vector.finding = "Request accepted without CAPTCHA token — client-side only"
        ctx.log("attack", "CRITICAL: CAPTCHA not validated server-side.")
        ctx.add_finding(Finding(
            title="CAPTCHA Not Enforced Server-Side",
            severity=Severity.CRITICAL,
            owasp_category="A07:2021 – Identification and Authentication Failures",
            cvss_score=9.1,
            description=(
                f"The login endpoint accepts authentication requests without a valid "
                f"{ctx.captcha_type.value} token. The CAPTCHA exists only in client-side "
                f"JavaScript and provides no protection against automation."
            ),
            evidence=(
                f"{form.method.upper()} {form.action_url} with '{captcha_field}' removed → "
                f"HTTP {response.status_code}, no CAPTCHA error in response."
            ),
            remediation=(
                "Validate the CAPTCHA token server-side on every auth request before "
                "processing credentials. Reject missing/invalid tokens with HTTP 400."
            ),
        ))
    else:
        ctx.captcha_enforcement = CaptchaEnforcement.SERVER_SIDE
        ctx.log("attack", "CAPTCHA appears enforced server-side. No bypass via token omission.")

    ctx.auth_vectors_tested.append(vector)


async def _test_rate_limiting(ctx: PentestContext, client: httpx.AsyncClient) -> None:
    ctx.log("attack", "Testing rate limiting on authentication endpoint...")
    form = _login(ctx)
    result = RateLimitResult(tested=True)
    request_count = 0
    batch_size = 20

    for i in range(batch_size):
        payload = _build_payload(form, "admin", f"brutetest_{i}")
        try:
            response = await _send(ctx, client, form, payload)
        except httpx.RequestError:
            break
        except Exception as e:  # ScopeError: budget hit — stop cleanly
            ctx.log("attack", f"Rate limit test stopped by scope policy: {e}")
            break

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

    result.requests_sent = request_count

    if not result.block_triggered and request_count > 0:
        result.notes = f"No rate limiting detected after {request_count} requests"
        ctx.log("attack", f"No rate limit or lockout after {request_count} requests. Flagging.")
        ctx.add_finding(Finding(
            title="No Rate Limiting on Authentication Endpoint",
            severity=Severity.HIGH,
            owasp_category="A07:2021 – Identification and Authentication Failures",
            cvss_score=7.5,
            description="The authentication endpoint does not enforce rate limiting, enabling brute-force.",
            evidence=f"{request_count} sequential failed logins with no 429 or lockout.",
            remediation=(
                "Rate-limit auth (e.g. 5 failed attempts/IP/min), return HTTP 429 with "
                "Retry-After, and consider progressive delays or CAPTCHA escalation."
            ),
        ))

    ctx.rate_limit_result = result


async def _test_user_enumeration(ctx: PentestContext, client: httpx.AsyncClient) -> None:
    ctx.log("attack", "Testing for user enumeration via response differences...")
    form = _login(ctx)
    timings = {}

    for username in ("admin", "nonexistent_xz99q"):
        payload = _build_payload(form, username, "wrongpassword_timing_test")
        start = time.monotonic()
        try:
            response = await _send(ctx, client, form, payload)
        except httpx.RequestError:
            continue
        except Exception as e:
            ctx.log("attack", f"Enumeration test stopped by scope policy: {e}")
            break
        timings[username] = {
            "time_ms": round((time.monotonic() - start) * 1000),
            "status": response.status_code,
            "body_length": len(response.text),
        }

    if len(timings) == 2:
        a, b = timings["admin"], timings["nonexistent_xz99q"]
        time_diff = abs(a["time_ms"] - b["time_ms"])
        body_diff = abs(a["body_length"] - b["body_length"])
        if time_diff > 300 or body_diff > 50:
            ctx.log("attack", f"Possible user enumeration: timing diff={time_diff}ms, body diff={body_diff}b")
            ctx.add_finding(Finding(
                title="Possible Username Enumeration",
                severity=Severity.MEDIUM,
                owasp_category="A07:2021 – Identification and Authentication Failures",
                cvss_score=5.3,
                description="Different responses for valid vs invalid usernames may allow enumeration.",
                evidence=(
                    f"'admin': {a['time_ms']}ms, {a['body_length']}b | "
                    f"'nonexistent': {b['time_ms']}ms, {b['body_length']}b"
                ),
                remediation="Return identical responses (timing, body, status) for all failed auth attempts.",
            ))
        else:
            ctx.log("attack", f"No significant enumeration signal (timing diff={time_diff}ms).")


def _get_captcha_field_name(captcha_type: CaptchaType) -> str:
    return {
        CaptchaType.RECAPTCHA_V2: "g-recaptcha-response",
        CaptchaType.RECAPTCHA_V3: "g-recaptcha-response",
        CaptchaType.HCAPTCHA: "h-captcha-response",
        CaptchaType.CUSTOM: "captcha",
        CaptchaType.NONE: "captcha",
    }.get(captcha_type, "captcha")
