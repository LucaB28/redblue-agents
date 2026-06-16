"""
core/llm.py

Thin wrapper around the Anthropic Claude API.

Design goals:
- The tool MUST run without an API key (graceful degradation to the
  deterministic heuristics). When a key is present, Claude adds reasoning
  on top: it plans the attack phase and writes the executive summary.
- One place to configure the model, retries and token budget.
- Never raises into the agents. Any error returns None and the caller
  falls back to deterministic behaviour.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional

DEFAULT_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
MAX_TOKENS = int(os.getenv("ANTHROPIC_MAX_TOKENS", "1024"))


class LLM:
    """Lazy Claude client. `enabled` is False when no key / SDK is available."""

    def __init__(self, use_llm: bool = True, model: str = DEFAULT_MODEL) -> None:
        self.model = model
        self.enabled = False
        self._client = None

        if not use_llm:
            return

        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            return

        try:
            import anthropic  # imported lazily so the dep is optional
        except ImportError:
            return

        try:
            self._client = anthropic.Anthropic(api_key=api_key)
            self.enabled = True
        except Exception:
            self.enabled = False

    def complete(self, system: str, prompt: str, max_tokens: int = MAX_TOKENS) -> Optional[str]:
        """Return the model's text response, or None on any failure."""
        if not self.enabled or self._client is None:
            return None
        try:
            msg = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
            parts = [block.text for block in msg.content if getattr(block, "type", None) == "text"]
            return "\n".join(parts).strip() or None
        except Exception:
            return None

    def complete_json(self, system: str, prompt: str, max_tokens: int = MAX_TOKENS) -> Optional[Any]:
        """Like complete(), but parses the response as JSON. None on failure."""
        raw = self.complete(
            system=system + "\n\nRespond with ONLY valid JSON. No markdown fences, no prose.",
            prompt=prompt,
            max_tokens=max_tokens,
        )
        if raw is None:
            return None
        return _loads_lenient(raw)


def _loads_lenient(raw: str) -> Optional[Any]:
    """Best-effort JSON parse that tolerates ```json fences and surrounding text."""
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1] if text.count("```") >= 2 else text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # last resort: grab the outermost {...} or [...]
        for opener, closer in (("{", "}"), ("[", "]")):
            start, end = text.find(opener), text.rfind(closer)
            if start != -1 and end > start:
                try:
                    return json.loads(text[start : end + 1])
                except json.JSONDecodeError:
                    continue
    return None
