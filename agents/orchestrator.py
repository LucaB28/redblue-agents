"""
agents/orchestrator.py

LangGraph graph definition. Connects Recon → Attack → Report with a single
shared PentestContext flowing through every node.

The nodes close over the caller-provided `ctx` so the shared-memory model is
exact and version-independent: every agent reads and writes the *same* object,
and the caller can read the final results directly from its own reference after
`graph.invoke()` returns.
"""

import asyncio

from langgraph.graph import StateGraph, END

from core.context import PentestContext
from agents.recon_agent import run_recon
from agents.attack_agent import run_attack
from agents.auth_agent import run_auth
from agents.report_agent import run_report


def should_abort(state) -> str:
    """Conditional edge: abort if recon failed."""
    abort = state.abort if hasattr(state, "abort") else state.get("abort", False)
    return "abort" if abort else "continue"


def build_graph(ctx: PentestContext, output_dir: str = "reports"):
    """Compile the agent graph bound to a specific shared context."""
    graph = StateGraph(PentestContext)

    def recon_node(_state):
        asyncio.run(run_recon(ctx))
        return ctx

    def attack_node(_state):
        asyncio.run(run_attack(ctx))
        return ctx

    def auth_node(_state):
        asyncio.run(run_auth(ctx))
        return ctx

    def report_node(_state):
        run_report(ctx, output_dir)
        return ctx

    def abort_node(_state):
        print(f"\n[orchestrator] Run aborted: {ctx.abort_reason}")
        return ctx

    graph.add_node("recon", recon_node)
    graph.add_node("attack", attack_node)
    graph.add_node("auth", auth_node)
    graph.add_node("report", report_node)
    graph.add_node("abort_node", abort_node)

    graph.set_entry_point("recon")
    graph.add_conditional_edges("recon", should_abort, {
        "continue": "attack",
        "abort": "abort_node",
    })
    graph.add_edge("attack", "auth")
    graph.add_edge("auth", "report")
    graph.add_edge("report", END)
    graph.add_edge("abort_node", END)

    return graph.compile()
