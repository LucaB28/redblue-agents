import pytest

from core.scope import ScopePolicy, ScopeError


def test_budget_cap_enforced():
    p = ScopePolicy(authorized=True, throttle_seconds=0, max_active_requests=2)
    p.before_active_request()
    p.before_active_request()
    with pytest.raises(ScopeError):
        p.before_active_request()
    assert p.requests_sent == 2


def test_in_scope_allows_target_host():
    p = ScopePolicy(authorized=True)
    p.assert_in_scope("https://app.example.com/login", "https://app.example.com/")


def test_out_of_scope_blocks_other_host():
    p = ScopePolicy(authorized=True)
    with pytest.raises(ScopeError):
        p.assert_in_scope("https://evil.example.net/login", "https://app.example.com/")


def test_allowed_host_extends_scope():
    p = ScopePolicy(authorized=True, allowed_hosts=["api.example.com"])
    p.assert_in_scope("https://api.example.com/login", "https://app.example.com/")


def test_authorization_required_non_interactive():
    p = ScopePolicy(authorized=False)
    with pytest.raises(ScopeError):
        p.require_authorization("https://app.example.com", interactive=False)


def test_authorized_flag_skips_prompt():
    p = ScopePolicy(authorized=True)
    p.require_authorization("https://app.example.com", interactive=False)  # no raise
