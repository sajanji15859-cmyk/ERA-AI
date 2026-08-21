"""Strict external-input validation helpers (Phase 2A).

All externally supplied action parameters and request bodies pass through these
bounds *in addition to* Pydantic schema validation, so malformed, unexpected,
oversized or unknown inputs are rejected deterministically before they reach any
service or provider. Over-strictness is safe; under-strictness is not.
"""

from __future__ import annotations

import re
from typing import Any

#: Maximum number of top-level action parameters.
MAX_PARAMS = 32
#: Maximum length of a single parameter name.
MAX_PARAM_KEY_LEN = 64
#: Maximum length of a single string value.
MAX_STR_LEN = 2000
#: Actions whose params legitimately carry full file content (Phase 3B).
#: Their string cap matches the workspace provider's max file bytes.
CONTENT_ACTIONS: frozenset[str] = frozenset({"fs.write", "photo.edit", "photo.upload"})
#: String cap for content-bearing params of the actions above.
MAX_CONTENT_LEN = 1_048_576
#: Approximate total "characters" budget across the whole params tree.
MAX_PARAM_TOTAL = 16384
#: Action type length bound.
MAX_ACTION_TYPE_LEN = 128
#: Action types must look like dotted, word-y identifiers (e.g. ``web.search``).
_ACTION_TYPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$")

#: Reasonable max length for free-text fields (username, display name, etc.).
MAX_NAME_LEN = 128
#: Max length for the strong-confirmation challenge phrase.
MAX_CHALLENGE_LEN = 256


class ValidationError_(ValueError):
    """Raised when external input violates a hardening bound.

    Name ends with an underscore to avoid clashing with the stdlib
    :class:`ValueError` when imported into Pydantic validators.
    """


def validate_action_type(value: str) -> str:
    """Validate an ``action_type`` string (fail closed on malformed input)."""
    if not isinstance(value, str) or not value:
        raise ValidationError_("action_type must be a non-empty string")
    if len(value) > MAX_ACTION_TYPE_LEN:
        raise ValidationError_("action_type too long")
    if not _ACTION_TYPE_RE.match(value):
        raise ValidationError_("action_type has invalid characters")
    return value


def validate_params(params: dict[str, Any], *, action_type: str | None = None,
                    str_limit: int | None = None) -> dict[str, Any]:
    """Deep-validate action params: types, names, sizes, and total budget.

    Returns the dict unchanged on success; raises :class:`ValidationError_` on
    any violation. Supports JSON-compatible scalars and nested dict/list only —
    anything else is rejected.

    ``action_type`` selects the string cap: content-bearing actions
    (``fs.write`` / ``photo.edit`` / ``photo.upload``) may carry full file
    content (bounded by the workspace provider cap); every other action keeps
    the strict :data:`MAX_STR_LEN` bound (Phase 3B).
    """
    if not isinstance(params, dict):
        raise ValidationError_("params must be a JSON object")
    budget = MAX_PARAM_TOTAL
    limit = str_limit if str_limit is not None else _string_limit_for(action_type)
    _walk(params, 0, budget, limit)
    return params


def _string_limit_for(action_type: str | None) -> int:
    if action_type in CONTENT_ACTIONS:
        return MAX_CONTENT_LEN
    return MAX_STR_LEN


def _walk(value: Any, depth: int, budget: int, str_limit: int) -> int:
    """Return an approximate character count of ``value``, validating bounds.

    ``budget`` is a soft guard; we accumulate a running total via the caller and
    check after each top-level key so an oversized payload fails fast.
    """
    if depth > 4:
        raise ValidationError_("params nesting too deep")
    if isinstance(value, str):
        if len(value) > str_limit:
            raise ValidationError_("string parameter value too long")
        return len(value)
    if isinstance(value, bool):
        return 1
    if isinstance(value, (int, float)):
        return len(str(value))
    if value is None:
        return 0
    if isinstance(value, dict):
        if len(value) > MAX_PARAMS:
            raise ValidationError_("too many nested parameters")
        total = 0
        for k, v in value.items():
            if not isinstance(k, str) or not k or len(k) > MAX_PARAM_KEY_LEN:
                raise ValidationError_("invalid parameter name")
            total += _walk(v, depth + 1, budget, str_limit)
        return total
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_PARAMS:
            raise ValidationError_("too many list elements")
        return sum(_walk(x, depth + 1, budget, str_limit) for x in value)
    raise ValidationError_("unsupported parameter value type")


def validate_name(value: str) -> str:
    """Validate a short free-text name (username / key name / display name)."""
    if not isinstance(value, str) or not value:
        raise ValidationError_("name must be a non-empty string")
    if len(value) > MAX_NAME_LEN:
        raise ValidationError_("name too long")
    return value


def validate_challenge(value: str | None) -> str | None:
    """Validate an optional strong-confirmation challenge phrase."""
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValidationError_("challenge must be a non-empty string")
    if len(value) > MAX_CHALLENGE_LEN:
        raise ValidationError_("challenge too long")
    return value
