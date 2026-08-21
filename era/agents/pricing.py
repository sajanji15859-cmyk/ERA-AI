"""LLM pricing estimation (Phase 3B).

Cost control is a core agent requirement. Real providers rarely report cost,
so the agent estimates it from usage tokens against a small, conservative
price table for common cheap models. Unknown models estimate 0 (never invent
a price). These estimates drive the run's USD cap
(``ERA_AGENT_COST_CAP_USD``) — a documented approximation, not billing.
"""

from __future__ import annotations

from typing import Any

#: USD per 1M tokens: (input/prompt, output/completion).
PRICING_USD_PER_MTOK: dict[str, tuple[float, float]] = {
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1-nano": (0.10, 0.40),
    "o4-mini": (1.10, 4.40),
    "llama-3.1-8b-instant": (0.05, 0.08),
    "llama-3.3-70b-versatile": (0.59, 0.79),
    "mixtral-8x7b-32768": (0.24, 0.24),
}

#: Chars-per-token heuristic when the provider reports no usage at all.
CHARS_PER_TOKEN = 4.0


def estimate_cost_usd(model: str | None, usage: dict[str, Any] | None) -> float:
    """Estimate USD cost from usage tokens, or 0.0 for unknown models."""
    if not usage:
        return 0.0
    price = PRICING_USD_PER_MTOK.get((model or "").lower())
    if price is None:
        return 0.0
    try:
        prompt = int(usage.get("prompt_tokens") or 0)
        completion = int(usage.get("completion_tokens") or 0)
    except (TypeError, ValueError):
        return 0.0
    return (prompt * price[0] + completion * price[1]) / 1_000_000.0


def usage_tokens(usage: dict[str, Any] | None, text: str = "") -> int:
    """Tokens from provider usage (total, or prompt+completion), else a
    char-length heuristic."""
    if usage:
        try:
            total = int(usage.get("total_tokens") or 0)
            if total > 0:
                return total
            prompt = int(usage.get("prompt_tokens") or 0)
            completion = int(usage.get("completion_tokens") or 0)
            if prompt + completion > 0:
                return prompt + completion
        except (TypeError, ValueError):
            pass
    return max(0, round(len(text or "") / CHARS_PER_TOKEN))


def usage_stats(model: str | None, usage: dict[str, Any] | None,
                text: str = "") -> tuple[int, float]:
    """Return ``(tokens, estimated_cost_usd)`` for one model response."""
    tokens = usage_tokens(usage, text)
    return tokens, estimate_cost_usd(model, usage)
