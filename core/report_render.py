"""
core/report_render.py

Turns findings into things a non-security friend can actually read:
  - a single letter grade (A+ .. F)
  - a self-contained HTML report (one file, opens in any browser)

UI labels are in Spanish for readability; technical finding text stays as-is.
"""

from __future__ import annotations

import html
from datetime import datetime

from core.context import PentestContext, Severity

# Points deducted from 100 per finding, by severity.
_WEIGHTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

_SEV_COLOR = {
    "CRITICAL": "#b00020",
    "HIGH": "#e65100",
    "MEDIUM": "#f9a825",
    "LOW": "#1565c0",
    "INFORMATIONAL": "#607d8b",
}

_SEV_ES = {
    "CRITICAL": "Crítico",
    "HIGH": "Alto",
    "MEDIUM": "Medio",
    "LOW": "Bajo",
    "INFORMATIONAL": "Informativo",
}

_WHY = {
    "CRITICAL": "Riesgo grave: explotable con poco esfuerzo. Arreglar de inmediato.",
    "HIGH": "Riesgo alto: debería arreglarse pronto.",
    "MEDIUM": "Riesgo medio: conviene corregirlo.",
    "LOW": "Riesgo bajo: mejora recomendada.",
    "INFORMATIONAL": "Informativo: sin riesgo directo.",
}

_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}


def compute_grade(findings) -> tuple[str, int]:
    """Return (letter_grade, score_0_100)."""
    score = 100 - sum(_WEIGHTS[f.severity] for f in findings)
    score = max(0, min(100, score))
    if score >= 95:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    return grade, score


def _grade_color(grade: str) -> str:
    return {
        "A+": "#1b8a3a", "A": "#1b8a3a", "B": "#7cb342",
        "C": "#f9a825", "D": "#e65100", "F": "#b00020",
    }.get(grade, "#607d8b")


def render_html(ctx: PentestContext, grade: str, score: int) -> str:
    findings = sorted(ctx.findings, key=lambda f: _ORDER[f.severity.value])
    counts = {s: sum(1 for f in findings if f.severity.value == s) for s in _ORDER}
    top3 = [f for f in findings if f.severity.value in ("CRITICAL", "HIGH", "MEDIUM")][:3]
    e = lambda s: html.escape(str(s))

    cards = "\n".join(_finding_card(f, e) for f in findings) or \
        "<p class='ok'>✅ No se detectaron problemas con los chequeos automáticos.</p>"

    top_html = "".join(
        f"<li><span class='dot' style='background:{_SEV_COLOR[f.severity.value]}'></span>"
        f"<b>{e(f.title)}</b> — {_WHY[f.severity.value]}</li>"
        for f in top3
    ) or "<li>Nada urgente. 👍</li>"

    chips = "".join(
        f"<span class='chip' style='border-color:{_SEV_COLOR[s]};color:{_SEV_COLOR[s]}'>"
        f"{_SEV_ES[s]}: {counts[s]}</span>"
        for s in _ORDER if counts[s]
    )

    auth_line = ""
    if ctx.authenticated is True:
        auth_line = "<p class='meta'>🔐 Escaneo autenticado: login exitoso.</p>"
    elif ctx.authenticated is False:
        auth_line = "<p class='meta'>🔐 Escaneo autenticado: no se pudo iniciar sesión.</p>"

    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe de seguridad — {e(ctx.target_url)}</title>
<style>
  :root {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }}
  body {{ margin:0; background:#f4f5f7; color:#1f2430; }}
  .wrap {{ max-width:860px; margin:0 auto; padding:24px 18px 60px; }}
  header {{ display:flex; align-items:center; gap:20px; background:#fff; border-radius:14px;
            padding:22px; box-shadow:0 1px 4px rgba(0,0,0,.08); }}
  .grade {{ width:96px; height:96px; border-radius:50%; display:flex; align-items:center;
            justify-content:center; font-size:42px; font-weight:800; color:#fff; flex:0 0 auto; }}
  h1 {{ font-size:20px; margin:0 0 4px; }}
  .meta {{ color:#5b6472; font-size:13px; margin:2px 0; }}
  .chips {{ margin:16px 0; }}
  .chip {{ display:inline-block; border:1px solid; border-radius:20px; padding:3px 12px;
           margin:4px 6px 0 0; font-size:13px; font-weight:600; }}
  .panel {{ background:#fff; border-radius:14px; padding:20px; margin-top:18px;
            box-shadow:0 1px 4px rgba(0,0,0,.08); }}
  .panel h2 {{ font-size:16px; margin:0 0 12px; }}
  ul.top {{ list-style:none; padding:0; margin:0; }}
  ul.top li {{ padding:8px 0; border-bottom:1px solid #eee; font-size:14px; }}
  .dot {{ display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:8px; }}
  details {{ border:1px solid #e6e8ec; border-radius:10px; margin:10px 0; overflow:hidden; }}
  summary {{ cursor:pointer; padding:12px 14px; font-weight:600; display:flex;
             align-items:center; gap:10px; list-style:none; }}
  summary::-webkit-details-marker {{ display:none; }}
  .sev {{ color:#fff; font-size:11px; font-weight:700; padding:2px 8px; border-radius:6px; }}
  .body {{ padding:0 14px 14px; font-size:14px; line-height:1.5; }}
  .body .lbl {{ font-weight:700; color:#3a4150; margin-top:10px; }}
  pre {{ background:#0f1320; color:#d6e0ff; padding:12px; border-radius:8px; overflow:auto;
         font-size:12.5px; }}
  .ok {{ font-size:16px; }}
  footer {{ color:#8a92a0; font-size:12px; text-align:center; margin-top:26px; }}
</style></head>
<body><div class="wrap">
  <header>
    <div class="grade" style="background:{_grade_color(grade)}">{grade}</div>
    <div>
      <h1>Informe de seguridad</h1>
      <p class="meta">Objetivo: <b>{e(ctx.target_url)}</b></p>
      <p class="meta">Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M')} · Puntaje: {score}/100 ·
         {len(findings)} hallazgo(s)</p>
      {auth_line}
    </div>
  </header>

  <div class="chips">{chips or '<span class="chip">Sin hallazgos</span>'}</div>

  <div class="panel">
    <h2>🔧 Arreglá primero</h2>
    <ul class="top">{top_html}</ul>
  </div>

  <div class="panel">
    <h2>📋 Hallazgos ({len(findings)})</h2>
    {cards}
  </div>

  <footer>Generado por redblue-agents · solo para pruebas autorizadas.<br>
  Detección heurística: confirmá manualmente antes de actuar.</footer>
</div></body></html>"""


def _finding_card(f, e) -> str:
    sev = f.severity.value
    color = _SEV_COLOR[sev]
    return f"""<details>
  <summary><span class="sev" style="background:{color}">{_SEV_ES[sev]}</span>
    {e(f.title)}</summary>
  <div class="body">
    <div class="lbl">Por qué importa</div>{_WHY[sev]}
    <div class="lbl">Qué es</div>{e(f.description)}
    <div class="lbl">Cómo arreglarlo</div>{e(f.remediation)}
    <div class="lbl">Evidencia</div><pre>{e(f.evidence)}</pre>
    <p class="meta">CVSS {f.cvss_score} · {e(f.owasp_category)}</p>
  </div>
</details>"""
