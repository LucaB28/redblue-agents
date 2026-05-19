"""
agents/orchestrator.py

LangGraph graph definition. Connects Recon → Attack → Report
with shared PentestContext flowing through every node.
"""

from langgraph.graph import StateGraph, END
from core.context import PentestContext
from agents.recon_agent import run_recon
from agents.attack_agent import run_attack
from agents.report_agent import run_report
import asyncio


def should_abort(ctx: PentestContext) -> str:
    """Conditional edge: abort if recon failed."""
    if ctx.abort:
        return "abort"
    return "continue"


def build_graph(output_dir: str = "reports"):
    graph = StateGraph(PentestContext)

    # Nodes
    graph.add_node("recon", lambda ctx: asyncio.run(run_recon(ctx)))
    graph.add_node("attack", lambda ctx: asyncio.run(run_attack(ctx)))
    graph.add_node("report", lambda ctx: _report_node(ctx, output_dir))
    graph.add_node("abort_node", _abort_node)

    # Edges
    graph.set_entry_point("recon")
    graph.add_conditional_edges("recon", should_abort, {
        "continue": "attack",
        "abort": "abort_node",
    })
    graph.add_edge("attack", "report")
    graph.add_edge("report", END)
    graph.add_edge("abort_node", END)

    return graph.compile()


def _report_node(ctx: PentestContext, output_dir: str) -> PentestContext:
    run_report(ctx, output_dir)
    return ctx


def _abort_node(ctx: PentestContext) -> PentestContext:
    print(f"\n[orchestrator] Run aborted: {ctx.abort_reason}")
    return ctx
