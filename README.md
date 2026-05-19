# 🔴🔵 redblue-agents

> **Multi-agent AI system for web application security analysis.**  
> Built with LangGraph + Claude API. Agents share memory across phases — recon feeds attack feeds report.

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square)
![LangGraph](https://img.shields.io/badge/LangGraph-0.2-green?style=flat-square)
![Claude](https://img.shields.io/badge/Claude-API-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-gray?style=flat-square)
![Status](https://img.shields.io/badge/Status-Research%20%2F%20Educational-red?style=flat-square)

---

## ⚠️ Disclaimer

This project is for **educational and authorized security research only**.  
Only run against systems you own or have explicit written permission to test.  
The authors are not responsible for misuse.

---

## The problem with existing tools

Burp Suite has been the industry standard for web security testing for 20+ years. Nuclei has thousands of templates. OWASP ZAP is free and battle-tested.

**None of them know what they found 30 seconds ago.**

These are deterministic tools. They execute predefined checks in a fixed sequence. Nuclei runs its 500 templates regardless of what the first 10 found. Burp's scanner doesn't stop testing CAPTCHA bypass vectors when it already confirmed the CAPTCH isn't enforced server-side — it keeps going mechanically.

That's not a criticism. It's just their design. They're built for coverage and repeatability, not reasoning.

**redblue-agents is a different category of tool.**

| | Burp Suite / Nuclei / ZAP | redblue-agents |
|---|---|---|
| Execution flow | Fixed, predefined sequence | Dynamic — built from recon findings |
| Memory between phases | None | Shared `PentestContext` across all agents |
| Decision making | Hardcoded rules | LLM reasons based on what was actually found |
| Redundant checks | Always runs everything | Stops a vector when finding is already confirmed |
| Output | Findings list | Findings + full agent reasoning chain |

The goal isn't to replace Burp. A security professional still needs Burp. The goal is to demonstrate what happens when you add **reasoning and shared memory** to the testing pipeline — and what that architecture looks like in practice.

---

## What makes this different from other "AI pentest" tools

Most repos in this space are LLM wrappers around nmap or scripted pipelines dressed up as agents. The pattern is always the same: Planner LLM → Recon → Attack → Report, in fixed order, no state shared between steps.

**redblue-agents implements actual shared state:**

1. Each agent has **its own memory** (what it found, what it tried, what failed)
2. Agents **share a global context** — the Recon Agent's findings directly shape the Attack Agent's strategy
3. The Attack Agent **stops testing redundant vectors** when a critical finding is already confirmed
4. The Report Agent **exposes the full reasoning chain**, not just results

The result: a system that behaves more like a junior pentester following a methodology than a script running checks in a loop.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Orchestrator Agent                        │
│                                                              │
│  Receives target URL → builds execution plan → coordinates  │
│  agent sequence → decides when to escalate or abort         │
└────────┬──────────────────────────┬──────────────────────────┘
         │                          │
         ▼                          ▼
┌─────────────────┐        ┌─────────────────────┐
│   Recon Agent   │        │    Attack Agent      │
│   (Blue side)   │        │    (Red side)        │
│                 │        │                      │
│ • HTTP headers  │──────▶ │ • Auth flow analysis │
│ • Tech stack    │  mem   │ • CAPTCHA impl check │
│ • Cookie flags  │        │ • Rate limit probing │
│ • CSP analysis  │        │ • Input validation   │
│ • CORS policy   │        │ • Session handling   │
└────────┬────────┘        └──────────┬───────────┘
         │                            │
         └──────────┬─────────────────┘
                    ▼
         ┌─────────────────────┐
         │    Report Agent     │
         │                     │
         │ • Consolidates all  │
         │   agent memories    │
         │ • Assigns CVSS base │
         │ • Maps to OWASP Top │
         │   10 categories     │
         │ • Generates markdown│
         │   report with chain │
         │   of thought        │
         └─────────────────────┘
```

### Shared Memory Model

This is the core of the architecture. Every agent reads and writes to a single `PentestContext` object that flows through the entire LangGraph graph:

```python
@dataclass
class PentestContext:
    target_url: str
    
    # Populated by Recon Agent
    tech_stack: list[str]
    security_headers: dict[str, HeaderAnalysis]
    captcha_detected: bool
    captcha_type: str | None          # recaptcha_v2 | recaptcha_v3 | hcaptcha | custom
    
    # Populated by Attack Agent — informed by recon findings
    auth_vectors_tested: list[AuthVector]
    captcha_enforcement: str | None   # client_only | server_side | missing
    rate_limit_behavior: RateLimitResult
    
    # Written by all agents, read by Report Agent
    findings: list[Finding]
    agent_reasoning: list[ReasoningStep]  # the chain of thought
```

The Attack Agent **doesn't decide what to test blindly** — it reads `captcha_detected`, `captcha_type`, and `tech_stack` from Recon and builds its test plan accordingly.

---

## CAPTCHA Analysis — A Case Study

One of the most misunderstood security controls. The interesting question isn't "can we solve it" — it's **"is it actually enforced server-side?"**

Most applications implement CAPTCHA in the frontend but forget to validate the token on the backend. The widget looks real. The protection isn't.

redblue-agents' Attack Agent checks four things about any CAPTCHA implementation:

| Check | What we test | Common finding |
|-------|-------------|----------------|
| **Server-side enforcement** | Remove CAPTCHA token from POST body entirely | Often still accepted |
| **Token reuse** | Replay a valid token on second request | Frequently reusable |
| **API endpoint bypass** | Does `/api/auth/login` also require CAPTCHA? | Often not |
| **Response manipulation** | Modify CAPTCHA validation response mid-request | Depends on implementation |

The agent logs its reasoning for each check — and stops when a critical finding is already confirmed:

```
[recon] CAPTCHA identified: recaptcha_v2
[attack] Reading recon memory: captcha=recaptcha_v2
[attack] Testing server-side enforcement: removed g-recaptcha-response from POST
[attack] CRITICAL: Request accepted without token. CAPTCHA is client-side only.
[attack] Skipping token reuse test — enforcement already confirmed missing. Moving to rate limit.
```

This is the memory model working: the agent **reasons about what it already knows** instead of running a fixed checklist.

---

## Installation

```bash
git clone https://github.com/yourusername/redblue-agents
cd redblue-agents
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # add your ANTHROPIC_API_KEY
```

### Run the target (Docker)

```bash
cd targets
docker-compose up -d
# DVWA available at http://localhost:8080
```

### Run redblue-agents

```bash
python main.py --target http://localhost:8080 --output reports/
```

---

## Sample Output

See [`reports/sample_report.md`](reports/sample_report.md) for a full example report generated against DVWA.

The reasoning chain section at the bottom is what makes it worth reading — every agent decision logged with its justification.

---

## Project Structure

```
redblue-agents/
├── main.py                     # entry point
├── agents/
│   ├── orchestrator.py         # LangGraph graph definition
│   ├── recon_agent.py          # passive analysis (blue side)
│   ├── attack_agent.py         # active testing (red side)
│   └── report_agent.py         # synthesis + CVSS scoring
├── core/
│   ├── context.py              # PentestContext — the shared memory model
│   └── tools.py                # HTTP tools used by agents
├── targets/
│   └── docker-compose.yml      # DVWA for local testing
├── reports/
│   └── sample_report.md        # example output
├── requirements.txt
└── .env.example
```

---

## Tech Stack

| Layer | Choice | Why |
|-------|--------|-----|
| Agent orchestration | LangGraph 0.2 | Stateful graph, visualizable execution |
| LLM | Claude claude-sonnet-4-20250514 | Best reasoning for multi-step analysis |
| HTTP tooling | httpx | Async, cleaner than requests for parallel agent ops |
| Report generation | Markdown + CVSS scoring | Portable, no external dependencies |
| Target | DVWA via Docker | Legal, reproducible, covers OWASP Top 10 |

---

## Why not just use Burp / Nuclei / ZAP?

You should. For real engagements, those tools are irreplaceable.

This project answers a different question: **what does a reasoning-capable, memory-sharing agent architecture look like when applied to security testing?**

The patterns here — shared context objects, agents that adapt based on prior findings, observable reasoning chains — are applicable beyond security. This is a concrete implementation of agentic AI design principles in a domain where the decisions are easy to understand and verify.

---

## Roadmap

- [ ] Playwright integration for JS-heavy login flows
- [ ] Multi-target batch mode
- [ ] HTML report with execution graph visualization
- [ ] Additional agents: API discovery, JWT analysis
- [ ] LangSmith tracing integration for full observability

---

## Related Work

- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [LangGraph Multi-Agent Docs](https://langchain-ai.github.io/langgraph/)
- [CVSS v3.1 Specification](https://www.first.org/cvss/specification-document)

---

*Built for security research and AI agent architecture experimentation. Not for offensive use.*
