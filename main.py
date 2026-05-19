"""
main.py — Phantom Pentest Agents entry point

Usage:
    python main.py --target http://localhost:8080 --output reports/
"""

import argparse
import asyncio
from core.context import PentestContext
from agents.orchestrator import build_graph


def main():
    parser = argparse.ArgumentParser(
        description="Phantom — AI agent-based web application security analysis"
    )
    parser.add_argument("--target", required=True, help="Target URL (must be authorized)")
    parser.add_argument("--output", default="reports", help="Output directory for reports")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════╗
║         PHANTOM PENTEST AGENTS           ║
║   AI-driven security analysis system    ║
║   For authorized testing only           ║
╚══════════════════════════════════════════╝

Target: {args.target}
""")

    ctx = PentestContext(target_url=args.target)
    graph = build_graph(output_dir=args.output)
    final_ctx = graph.invoke(ctx)

    print(f"\n✅ Done. {len(final_ctx.findings)} findings. Report in '{args.output}/'")


if __name__ == "__main__":
    main()
