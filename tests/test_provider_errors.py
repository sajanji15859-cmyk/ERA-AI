"""Phase 1E: ProviderErrorCode and ToolError error semantics."""

from __future__ import annotations

import pytest

from era.core.result import ProviderErrorCode, ToolError


def test_error_codes_are_stable_strings():
    # Codes are StrEnums so they serialise deterministically into audit/JSON.
    assert ProviderErrorCode.TIMEOUT.value == "TIMEOUT"
    assert ProviderErrorCode.VALIDATION.value == "VALIDATION"
    assert ProviderErrorCode.AUTH.value == "AUTH"
    for code in ProviderErrorCode:
        assert isinstance(code.value, str)
        assert code.value == code.value.upper()


def test_toolerror_defaults_to_provider_error():
    err = ToolError("boom")
    assert str(err) == "boom"
    assert err.provider_id is None
    assert err.code is ProviderErrorCode.PROVIDER_ERROR


def test_toolerror_accepts_specific_code():
    err = ToolError("nope", provider_id="web", code=ProviderErrorCode.FORBIDDEN)
    assert err.provider_id == "web"
    assert err.code is ProviderErrorCode.FORBIDDEN


def test_toolerror_accepts_string_code():
    err = ToolError("slow", code="TIMEOUT")
    assert err.code is ProviderErrorCode.TIMEOUT


def test_toolerror_unknown_string_code_falls_back():
    err = ToolError("weird", code="VENDOR_SPECIFIC_WAT")
    assert err.code is ProviderErrorCode.PROVIDER_ERROR


@pytest.mark.parametrize("code", list(ProviderErrorCode))
def test_every_code_is_raisable(code):
    err = ToolError("x", code=code)
    assert err.code is code
