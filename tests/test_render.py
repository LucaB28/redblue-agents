from core.context import PentestContext, Finding, Severity
from core.report_render import compute_grade, render_html


def _f(sev):
    return Finding("T " + sev.value, sev, "OWASP", 5.0, "desc", "evi", "fix")


def test_grade_perfect_when_no_findings():
    assert compute_grade([]) == ("A+", 100)


def test_grade_drops_with_critical():
    grade, score = compute_grade([_f(Severity.CRITICAL)])
    assert score == 60
    assert grade == "D"


def test_grade_floored_at_zero():
    grade, score = compute_grade([_f(Severity.CRITICAL)] * 5)
    assert score == 0
    assert grade == "F"


def test_render_html_contains_grade_and_target():
    ctx = PentestContext(target_url="https://app.example.com")
    ctx.add_finding(_f(Severity.HIGH))
    grade, score = compute_grade(ctx.findings)
    out = render_html(ctx, grade, score)
    assert "<!doctype html>" in out
    assert "app.example.com" in out
    assert grade in out


def test_render_html_escapes_evidence():
    ctx = PentestContext(target_url="https://x.example.com")
    ctx.add_finding(Finding("XSS test", Severity.LOW, "O", 3.0, "d", "<script>bad</script>", "fix"))
    out = render_html(ctx, *compute_grade(ctx.findings))
    assert "<script>bad" not in out
    assert "&lt;script&gt;" in out
