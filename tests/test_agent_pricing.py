"""LLM pricing estimation tests (Phase 3B)."""

from __future__ import annotations

import pytest

from era.agents.pricing import estimate_cost_usd, usage_stats, usage_tokens


def test_known_model_cost_from_usage():
    usage = {"prompt_tokens": 1_000, "completion_tokens": 2_000, "total_tokens": 3_000}
    cost = estimate_cost_usd("gpt-4o-mini", usage)
    assert cost == pytest.approx((1000 * 0.15 + 2000 * 0.60) / 1e6)


def test_unknown_model_costs_zero():
    assert estimate_cost_usd("mystery-model", {"total_tokens": 10_000}) == 0.0


def test_missing_usage_costs_zero():
    assert estimate_cost_usd("gpt-4o-mini", None) == 0.0
    assert estimate_cost_usd("gpt-4o-mini", {}) == 0.0


def test_bad_usage_values_fail_closed():
    assert estimate_cost_usd("gpt-4o-mini", {"prompt_tokens": "lots"}) == 0.0


def test_usage_tokens_prefers_provider_total():
    assert usage_tokens({"total_tokens": 120}, "ignored") == 120


def test_usage_tokens_falls_back_to_chars():
    assert usage_tokens(None, "x" * 400) == 100


def test_usage_stats_roundtrip():
    tokens, cost = usage_stats("gpt-4o-mini", {"prompt_tokens": 500, "completion_tokens": 500})
    assert tokens == 1000
    assert cost > 0
