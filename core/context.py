"""
core/context.py

Shared memory model. This is what flows between agents.
Every agent reads from here and writes back to here.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFORMATIONAL"


class CaptchaType(str, Enum):
    RECAPTCHA_V2 = "recaptcha_v2"
    RECAPTCHA_V3 = "recaptcha_v3"
    HCAPTCHA = "hcaptcha"
    CUSTOM = "custom"
    NONE = "none"


class CaptchaEnforcement(str, Enum):
    CLIENT_ONLY = "client_only"       # worst case — CAPTCHA is cosmetic
    SERVER_SIDE = "server_side"       # actually validated
    MISSING = "missing"               # no CAPTCHA at all
    UNKNOWN = "unknown"


@dataclass
class HeaderAnalysis:
    name: str
    present: bool
    value: Optional[str] = None
    risk_note: Optional[str] = None


@dataclass
class LoginForm:
    """A login form discovered on the target by the recon agent."""
    action_url: str
    method: str = "post"
    username_field: str = "username"
    password_field: str = "password"
    captcha_field: Optional[str] = None
    extra_fields: dict = field(default_factory=dict)  # hidden inputs (CSRF, etc.)


@dataclass
class AuthVector:
    """A single auth test the attack agent performed."""
    name: str
    description: str
    request_summary: str
    response_code: int
    finding: Optional[str] = None  # None if no issue found


@dataclass
class RateLimitResult:
    tested: bool = False
    requests_sent: int = 0
    block_triggered: bool = False
    block_at_request: Optional[int] = None
    notes: str = ""


@dataclass
class Finding:
    title: str
    severity: Severity
    owasp_category: str
    cvss_score: float
    description: str
    evidence: str
    remediation: str


@dataclass
class ReasoningStep:
    """One logged reasoning step from any agent. Surfaced in final report."""
    agent: str
    message: str


@dataclass
class PentestContext:
    """
    The shared brain. Instantiated by the Orchestrator and passed
    through every node in the LangGraph graph.
    
    Agents READ from previous phases and WRITE their own findings.
    The Report Agent reads everything.
    """
    target_url: str

    # --- Populated by Recon Agent ---
    tech_stack: list[str] = field(default_factory=list)
    security_headers: dict[str, HeaderAnalysis] = field(default_factory=dict)
    captcha_detected: bool = False
    captcha_type: CaptchaType = CaptchaType.NONE
    cookies_analyzed: dict[str, dict] = field(default_factory=dict)
    cors_policy: Optional[str] = None
    login_form: Optional["LoginForm"] = None

    # --- Populated by Attack Agent (informed by recon) ---
    auth_vectors_tested: list[AuthVector] = field(default_factory=list)
    captcha_enforcement: CaptchaEnforcement = CaptchaEnforcement.UNKNOWN
    rate_limit_result: RateLimitResult = field(default_factory=RateLimitResult)

    # --- Written by all agents, consumed by Report Agent ---
    findings: list[Finding] = field(default_factory=list)
    reasoning_chain: list[ReasoningStep] = field(default_factory=list)

    # --- Orchestrator control ---
    abort: bool = False
    abort_reason: Optional[str] = None

    # --- Injected config (not serialized into findings) ---
    scope: object = None      # core.scope.ScopePolicy
    llm: object = None        # core.llm.LLM
    llm_notes: list = field(default_factory=list)  # narrative lines authored by Claude

    def log(self, agent: str, message: str) -> None:
        """Append a reasoning step. Called by any agent at any point."""
        self.reasoning_chain.append(ReasoningStep(agent=agent, message=message))
        print(f"[{agent}] {message}")

    def add_finding(self, finding: Finding) -> None:
        # Deduplicate by title so re-runs / overlapping checks don't double-report.
        if any(f.title == finding.title for f in self.findings):
            return
        self.findings.append(finding)
        self.log("context", f"Finding added: [{finding.severity.value}] {finding.title}")
