"""Tests for BookingProvider safe draft and approval model (Phase 3H)."""

from __future__ import annotations

import pytest

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.enums import Decision
from era.core.result import ProviderErrorCode, ToolError
from era.providers.booking import BookingProvider
from tests.conftest import make_container
from tests.provider_contract import assert_provider_contract


@pytest.fixture
def provider():
    return BookingProvider()


def test_booking_provider_contract(provider):
    sample = Action(
        action_type="booking.search",
        params={"origin": "NDLS", "destination": "MMCT"},
    )
    assert_provider_contract(provider, sample_action=sample)


def test_booking_search(provider):
    a = Action(
        action_type="booking.search",
        params={"origin": "NDLS", "destination": "BCT", "date": "2026-09-15", "mode": "train"},
    )
    result = provider.execute(a, ExecutionContext(actor_id="test"))
    assert result.success is True
    assert result.data["count"] >= 2
    assert "Rajdhani" in result.data["results"][0]["name"]
    assert result.data["results"][0]["fare_inr"] > 0


def test_booking_draft_hold_and_confirm_flow(provider):
    # 1. Hold a draft
    hold_act = Action(
        action_type="booking.hold",
        params={
            "trip_id": "TRN-12951-NDLS-MMCT",
            "passenger_name": "Rohan Sharma",
            "fare": 2180.0,
        },
    )
    hold_res = provider.execute(hold_act, ExecutionContext(actor_id="test"))
    assert hold_res.success is True
    draft_id = hold_res.data["draft_id"]
    assert draft_id.startswith("DRAFT-")
    assert hold_res.data["status"] == "held"

    # 2. Confirm booking with draft_id
    confirm_act = Action(
        action_type="booking.confirm",
        params={"draft_id": draft_id},
    )
    confirm_res = provider.execute(confirm_act, ExecutionContext(actor_id="test"))
    assert confirm_res.success is True
    assert confirm_res.data["status"] == "confirmed"
    assert confirm_res.data["pnr"].startswith("PNR")
    booking_id = confirm_res.data["booking_id"]

    # 3. Cancel booking
    cancel_act = Action(
        action_type="booking.cancel",
        params={"booking_id": booking_id},
    )
    cancel_res = provider.execute(cancel_act, ExecutionContext(actor_id="test"))
    assert cancel_res.success is True
    assert cancel_res.data["status"] == "cancelled"
    assert cancel_res.data["refund_inr"] > 0


def test_booking_confirm_and_cancel_require_confirm_strong(tmp_path):
    """End-to-end gate: booking.confirm and booking.cancel require CONFIRM_STRONG."""
    c = make_container(tmp_path, providers=[BookingProvider()])

    # booking.confirm -> confirmation_required + challenge phrase
    confirm_act = Action(
        action_type="booking.confirm",
        params={"draft_id": "DRAFT-1234"},
    )
    resp = c.execution_service.request(confirm_act, ExecutionContext(actor_id="alice"))
    assert resp.status == "confirmation_required"
    assert resp.decision == Decision.CONFIRM_STRONG
    assert resp.challenge is not None
    assert len(resp.challenge) > 5

    # booking.cancel -> confirmation_required + challenge phrase
    cancel_act = Action(
        action_type="booking.cancel",
        params={"booking_id": "BK-1234"},
    )
    resp_cancel = c.execution_service.request(cancel_act, ExecutionContext(actor_id="alice"))
    assert resp_cancel.status == "confirmation_required"
    assert resp_cancel.decision == Decision.CONFIRM_STRONG
    assert resp_cancel.challenge is not None


def test_booking_validation_errors(provider):
    # Missing destination
    with pytest.raises(ToolError) as exc:
        provider.validate(Action(action_type="booking.search", params={"origin": "DEL"}))
    assert exc.value.code == ProviderErrorCode.VALIDATION

    # Missing booking_id for cancel
    with pytest.raises(ToolError) as exc:
        provider.validate(Action(action_type="booking.cancel", params={}))
    assert exc.value.code == ProviderErrorCode.VALIDATION
