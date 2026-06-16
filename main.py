"""
main.py — redblue-agents entry point

Quick start:
    pip install -r requirements.txt
    cp .env.example .env          # add ANTHROPIC_API_KEY (optional)
    python main.py --target https://your-app.example.com --authorized

Run `python main.py --help` for all options.
"""

import argparse
import sys

from dotenv import load_dotenv

from core.context import PentestContext
from core.scope import ScopePolicy, ScopeError
from core.llm import LLM
from agents.orchestrator import build_graph

BANNER = r"""
╔══════════════════════════════════════════╗
║              redblue-agents              ║
║   AI-assisted web auth security analysis ║
║      For AUTHORIZED testing only         ║
╚══════════════════════════════════════════╝
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="redblue-agents — multi-agent web authentication security analysis",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--target", required=True, help="Target URL (must be authorized)")
    p.add_argument("--output", default="reports", help="Output directory for reports")
    p.add_argument("--authorized", action="store_true",
                   help="Confirm you have written permission to test the target (skips prompt)")
    p.add_argument("--allow-host", action="append", default=[], metavar="HOST",
                   help="Extra in-scope host (repeatable). Target host is always allowed.")
    p.add_argument("--throttle", type=float, default=0.2,
                   help="Minimum seconds between active requests")
    p.add_argument("--max-requests", type=int, default=60,
                   help="Hard cap on total active requests for the run")
    p.add_argument("--no-llm", action="store_true",
                   help="Disable Claude reasoning; use deterministic heuristics only")
    p.add_argument("--model", default=None, help="Override ANTHROPIC_MODEL")
    return p


def main() -> int:
    load_dotenv()
    args = build_parser().parse_args()

    print(BANNER)
    print(f"Target: {args.target}\n")

    scope = ScopePolicy(
        authorized=args.authorized,
        allowed_hosts=args.allow_host,
        throttle_seconds=args.throttle,
        max_active_requests=args.max_requests,
    )
    try:
        scope.require_authorization(args.target)
    except ScopeError as e:
        print(f"❌ {e}")
        return 2

    llm = LLM(use_llm=not args.no_llm, model=args.model) if args.model else LLM(use_llm=not args.no_llm)
    if llm.enabled:
        print(f"🧠 Claude reasoning enabled (model: {llm.model})\n")
    else:
        print("🔧 Running in deterministic mode (no ANTHROPIC_API_KEY or --no-llm).\n")

    ctx = PentestContext(target_url=args.target)
    ctx.scope = scope
    ctx.llm = llm

    # Nodes close over `ctx`, so results land on our own reference.
    graph = build_graph(ctx, output_dir=args.output)
    graph.invoke(ctx)

    if ctx.abort:
        print(f"\n⛔ Run aborted: {ctx.abort_reason}")
        return 1

    print(
        f"\n✅ Done. {len(ctx.findings)} finding(s), "
        f"{scope.requests_sent} active request(s) sent. Report in '{args.output}/'"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
