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
#: Actions whose params legitimately carry full file content (Phase 3B/3D).
#: Their string cap matches the workspace provider's max file bytes.
CONTENT_ACTIONS: frozenset[str] = frozenset({
    "fs.write",
    "photo.edit",
    "photo.upload",
    "github.file_commit",
    "code.run",
    "code.exec",
})
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


_PARAM_ALIASES: dict[str, tuple[str, ...]] = {
    "q": ("query",),
    "content": ("content_from",),
}


def validate_param_schema(params: dict[str, Any], schema: dict[str, Any] | None) -> dict[str, Any]:
    """Validate action parameters against the action's ActionSpec.param_schema.

    Enforces fail-closed rules (Phase 3H):
    * Missing required parameters -> ValidationError_
    * Unknown parameters (when properties declared and additionalProperties is not True) -> ValidationError_
    * Wrong types (string, integer, number, boolean, array, object) -> ValidationError_
    * Violations of enum, minLength, maxLength, minimum, maximum -> ValidationError_
    * ``oneOf`` required/not shape constraints must match exactly one branch.
    """
    if schema is None:
        return params
    if not isinstance(params, dict):
        raise ValidationError_("params must be a JSON object")

    required = schema.get("required") or []
    for req in required:
        has_field = req in params and params[req] is not None
        if not has_field:
            aliases = _PARAM_ALIASES.get(req, ())
            if not any(alias in params and params[alias] is not None for alias in aliases):
                raise ValidationError_(f"missing required parameter: {req!r}")

    properties = schema.get("properties")
    allow_additional = schema.get("additionalProperties", properties is None)

    if properties is not None:
        for k, v in params.items():
            if k not in properties:
                if not allow_additional:
                    raise ValidationError_(f"unknown parameter: {k!r}")
                continue
            prop_spec = properties[k]
            expected_type = prop_spec.get("type")
            if expected_type:
                _check_prop_type(k, v, expected_type)
            if "enum" in prop_spec and v not in prop_spec["enum"]:
                raise ValidationError_(f"parameter {k!r} must be one of {prop_spec['enum']}")
            if "minLength" in prop_spec and isinstance(v, str) and len(v) < prop_spec["minLength"]:
                raise ValidationError_(f"parameter {k!r} must be at least {prop_spec['minLength']} chars")
            if "maxLength" in prop_spec and isinstance(v, str) and len(v) > prop_spec["maxLength"]:
                raise ValidationError_(f"parameter {k!r} must be at most {prop_spec['maxLength']} chars")
            if "minimum" in prop_spec and isinstance(v, (int, float)) and v < prop_spec["minimum"]:
                raise ValidationError_(f"parameter {k!r} must be >= {prop_spec['minimum']}")
            if "maximum" in prop_spec and isinstance(v, (int, float)) and v > prop_spec["maximum"]:
                raise ValidationError_(f"parameter {k!r} must be <= {prop_spec['maximum']}")

    one_of = schema.get("oneOf")
    if isinstance(one_of, list):
        matches = sum(
            1 for condition in one_of
            if isinstance(condition, dict) and _matches_schema_condition(params, condition)
        )
        if matches != 1:
            raise ValidationError_("parameters must satisfy exactly one allowed schema shape")

    # ``allOf``: every branch must match (Phase 4B — independent constraints such
    # as browser.fill's target XOR value shapes cannot be encoded in a single
    # flat ``oneOf``). Branches are validated with the same required/not subset.
    all_of = schema.get("allOf")
    if isinstance(all_of, list):
        for condition in all_of:
            if not isinstance(condition, dict):
                raise ValidationError_("invalid allOf condition in action schema")
            nested_one_of = condition.get("oneOf")
            if isinstance(nested_one_of, list):
                nested_matches = sum(
                    1 for branch in nested_one_of
                    if isinstance(branch, dict)
                    and _matches_schema_condition(params, branch)
                )
                if nested_matches != 1:
                    raise ValidationError_(
                        "parameters must satisfy exactly one allowed schema shape"
                    )
                continue
            if not _matches_schema_condition(params, condition):
                raise ValidationError_("parameters do not satisfy the required schema shape")

    return params


def _matches_schema_condition(params: dict[str, Any], condition: dict[str, Any]) -> bool:
    """Match the small ``required``/``not``/``anyOf`` subset used by strict
    action schemas (``anyOf`` added for Phase 4B "at most one of" shapes)."""

    required = condition.get("required", [])
    if not isinstance(required, list) or not all(
        isinstance(key, str) and key in params and params[key] is not None
        for key in required
    ):
        return False
    any_of = condition.get("anyOf")
    if (isinstance(any_of, list)
            and not any(isinstance(sub, dict)
                        and _matches_schema_condition(params, sub)
                        for sub in any_of)):
        return False
    negated = condition.get("not")
    return not (isinstance(negated, dict) and _matches_schema_condition(params, negated))


def _check_prop_type(param_name: str, value: Any, expected_type: str) -> None:
    if value is None:
        return
    if expected_type == "string":
        if not isinstance(value, str):
            raise ValidationError_(
                f"parameter {param_name!r} must be a string, got {type(value).__name__}"
            )
    elif expected_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValidationError_(
                f"parameter {param_name!r} must be an integer, got {type(value).__name__}"
            )
    elif expected_type == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ValidationError_(
                f"parameter {param_name!r} must be a number, got {type(value).__name__}"
            )
    elif expected_type == "boolean":
        if not isinstance(value, bool):
            raise ValidationError_(
                f"parameter {param_name!r} must be a boolean, got {type(value).__name__}"
            )
    elif expected_type == "array":
        if not isinstance(value, (list, tuple)):
            raise ValidationError_(
                f"parameter {param_name!r} must be an array, got {type(value).__name__}"
            )
    elif expected_type == "object" and not isinstance(value, dict):
        raise ValidationError_(
            f"parameter {param_name!r} must be an object, got {type(value).__name__}"
        )


def validate_challenge(value: str | None) -> str | None:
    """Validate an optional strong-confirmation challenge phrase."""
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValidationError_("challenge must be a non-empty string")
    if len(value) > MAX_CHALLENGE_LEN:
        raise ValidationError_("challenge too long")
    return value
