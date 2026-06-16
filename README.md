# 🔴🔵 redblue-agents

> **Multi-agent web authentication security analyzer.**
> Recon → Attack → Report, sharing one memory. Optional Claude reasoning on top.

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square)
![LangGraph](https://img.shields.io/badge/LangGraph-0.2-green?style=flat-square)
![Claude](https://img.shields.io/badge/Claude-optional-orange?style=flat-square)
![Tests](https://img.shields.io/badge/tests-pytest-blueviolet?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-gray?style=flat-square)

Point it at a login page you own and it returns a Markdown report: missing
security headers, insecure cookies, tech-stack disclosure, CAPTCHA that isn't
enforced server-side, missing rate limiting, and username enumeration — each
with severity, CVSS, OWASP category, evidence and a fix.

It runs **without any API key** (deterministic checks). Add an
`ANTHROPIC_API_KEY` and Claude additionally plans the attack phase and writes
the executive summary.

---

## ⚠️ Authorized use only

Active testing against a system you don't own — or don't have **written
permission** to test — is illegal in most countries. The tool refuses to start
until you confirm authorization (`--authorized` or an interactive prompt), keeps
every request on the target host, throttles itself, and caps total requests.

---

## Quick start (3 steps)

```bash
# 1. Clone + install
git clone https://github.com/LucaB28/redblue-agents
cd redblue-agents
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. (optional) enable Claude reasoning
cp .env.example .env          # then paste your ANTHROPIC_API_KEY into .env

# 3. Scan a site you are authorized to test
python main.py --target https://your-app.example.com --authorized
```

The report is written to `reports/report_<timestamp>.md`.

> No key? It still works — you'll see `Running in deterministic mode` and get
> the same checks minus the LLM narrative.

### Try it safely against a local target

```bash
cd targets && docker compose up -d        # DVWA at http://localhost:8080
python main.py --target http://localhost:8080 --authorized
```

---

## Validating *your* login / web app

The recon agent reads the page HTML and auto-detects the login form — its real
action URL and the actual `username` / `password` / CSRF field names — so you
usually only need the target URL:

```bash
python main.py --target https://app.mycompany.com/login --authorized
```

Useful flags (`python main.py --help` for all):

| Flag | Purpose | Default |
|------|---------|---------|
| `--authorized` | Confirm permission, skip the prompt (use in CI) | off |
| `--allow-host HOST` | Add an extra in-scope host (e.g. an API subdomain) | target only |
| `--throttle SECONDS` | Minimum delay between active requests | `0.2` |
| `--max-requests N` | Hard cap on total active requests | `60` |
| `--no-llm` | Force deterministic mode even with a key set | off |
| `--output DIR` | Report directory | `reports` |

---

## What it checks

| Area | Check | Severity if found |
|------|-------|-------------------|
| Headers | CSP / X-Frame-Options / HSTS / etc. missing | Medium |
| Cookies | Missing `HttpOnly` / `Secure` / `SameSite` | Medium |
| Disclosure | `X-Powered-By` / `Server` leakage | Low |
| CORS | `Access-Control-Allow-Origin: *` | Medium |
| CAPTCHA | Token not validated server-side (omit it, still accepted) | **Critical** |
| Rate limiting | No 429 / lockout after rapid auth attempts | High |
| Enumeration | Valid vs invalid usernames differ in timing/body | Medium |

---

## How it works

```
Orchestrator (LangGraph)
   │
   ▼
Recon  ── shared PentestContext ──▶  Attack  ──▶  Report
(blue)                               (red)        (markdown + reasoning)
```

- **Shared memory** — every agent reads/writes one `PentestContext` object.
  Recon's findings (CAPTCHA type, login form, tech stack) directly shape the
  Attack agent's plan.
- **Adaptive, not a fixed checklist** — the Attack agent skips CAPTCHA tests
  when none was detected, and skips rate-limit tests when CAPTCHA is already
  enforced server-side.
- **Optional Claude reasoning** — with a key, `core/llm.py` lets Claude pick the
  test plan from recon evidence and write the executive summary. Detection stays
  deterministic: the model never invents a finding or a CVSS score.
- **Safety layer** — `core/scope.py` gates authorization and enforces host
  allowlist, throttle and a request budget on every active request.

See [`reports/sample_report.md`](reports/sample_report.md) for example output.

---

## Project structure

```
redblue-agents/
├── main.py                  # CLI entry point
├── agents/
│   ├── orchestrator.py      # LangGraph graph (nodes share one ctx)
│   ├── recon_agent.py       # passive analysis + login-form discovery
│   ├── attack_agent.py      # active auth tests (scope-guarded)
│   └── report_agent.py      # markdown report + exec summary
├── core/
│   ├── context.py           # PentestContext — the shared memory model
│   ├── forms.py             # login-form auto-detection (bs4 + regex fallback)
│   ├── scope.py             # authorization / throttle / budget controls
│   └── llm.py               # optional Claude wrapper (graceful fallback)
├── targets/docker-compose.yml
├── tests/                   # pytest suite
└── .github/workflows/ci.yml
```

---

## Development

```bash
pip install -r requirements-dev.txt
pytest -q
```

CI runs the suite on Python 3.11 and 3.12 (`.github/workflows/ci.yml`).

---

## Limitations

- Heuristic detection — confirm findings manually before reporting them.
- Single-step login only; JS-heavy SPA flows aren't driven yet (roadmap).
- Not a replacement for Burp / ZAP / Nuclei. It's a focused auth analyzer with
  a shared-memory agent architecture you can read and extend.

## Roadmap

- [ ] Playwright for JS-heavy login flows
- [ ] Multi-target batch mode
- [ ] HTML report with execution graph
- [ ] API discovery + JWT analysis agents

---

## License

MIT — see [LICENSE](LICENSE).

*For authorized security research and AI agent architecture experimentation only.*
