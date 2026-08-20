"""Minimal JSON-schema-subset validator for tool arguments (stdlib only).

Supported constructs (everything else fails *closed* with a clear error):

* ``type``: ``string`` | ``integer`` | ``number`` | ``boolean`` | ``array`` | ``object``
* ``properties`` (+ nested schemas), ``required``
* ``additionalProperties: false`` — rejects unknown keys (keeps LLMs honest)
* ``enum``, ``minLength`` / ``maxLength`` (strings), ``minimum`` / ``maximum`` (numbers),
  ``items`` (arrays)

Tool *arguments* are always objects, so the top-level schema must be ``type: object``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

_TYPE_NAMES = ("string", "integer", "number", "boolean", "array", "object", "null")
_TYPES: dict[str, tuple[type[Any], ...]] = {
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "array": (list,),
    "object": (dict,),
    "null": (type(None),),
}


def validate_schema(
    instance: Any, schema: Mapping[str, Any], where: str = "arguments"
) -> list[str]:
    """Validate ``instance`` against ``schema``; return a list of human-readable errors."""
    errors: list[str] = []
    _validate(instance, schema, where, errors)
    return errors


def _validate(instance: Any, schema: Mapping[str, Any], where: str, errors: list[str]) -> None:
    if not isinstance(schema, Mapping):
        errors.append(f"{where}: schema must be an object")
        return

    expected_type = schema.get("type")
    if expected_type is not None:
        _check_type(instance, expected_type, where, errors)
        if errors and where == "arguments":
            return  # structure unusable; skip further checks on this branch

    if "enum" in schema and not any(instance == option for option in schema["enum"]):
        allowed = ", ".join(repr(o) for o in schema["enum"])
        errors.append(f"{where}: must be one of {allowed}")

    if isinstance(instance, str):
        _check_bounds_str(instance, schema, where, errors)

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        _check_bounds_num(instance, schema, where, errors)

    if expected_type == "object" and isinstance(instance, Mapping):
        _validate_object(instance, schema, where, errors)

    if (
        expected_type == "array"
        and isinstance(instance, Sequence)
        and not isinstance(instance, str)
    ):
        items_schema = schema.get("items")
        if items_schema is not None:
            for index, item in enumerate(instance):
                _validate(item, items_schema, f"{where}[{index}]", errors)


def _check_type(instance: Any, expected: str, where: str, errors: list[str]) -> None:
    if expected not in _TYPE_NAMES:
        errors.append(f"{where}: schema uses unsupported type {expected!r}")
        return
    allowed_types = _TYPES[expected]
    # bool is a subclass of int in Python — never accept a bool for integer/number.
    if isinstance(instance, bool) and expected in ("integer", "number"):
        errors.append(f"{where}: must be {expected}, got boolean")
        return
    if not isinstance(instance, allowed_types):
        actual = _type_name_of(instance)
        errors.append(f"{where}: must be {expected}, got {actual}")


def _type_name_of(instance: Any) -> str:
    for name, types in _TYPES.items():
        if isinstance(instance, types):
            return name if not isinstance(instance, bool) or name == "boolean" else "integer"
    return type(instance).__name__


def _check_bounds_str(
    instance: str, schema: Mapping[str, Any], where: str, errors: list[str]
) -> None:
    min_length = schema.get("minLength")
    max_length = schema.get("maxLength")
    if min_length is not None and len(instance) < min_length:
        errors.append(f"{where}: length {len(instance)} is shorter than minLength {min_length}")
    if max_length is not None and len(instance) > max_length:
        errors.append(f"{where}: length {len(instance)} exceeds maxLength {max_length}")


def _check_bounds_num(
    instance: int | float, schema: Mapping[str, Any], where: str, errors: list[str]
) -> None:
    minimum = schema.get("minimum")
    maximum = schema.get("maximum")
    if minimum is not None and instance < minimum:
        errors.append(f"{where}: value {instance} is below minimum {minimum}")
    if maximum is not None and instance > maximum:
        errors.append(f"{where}: value {instance} exceeds maximum {maximum}")


def _validate_object(
    instance: Mapping[str, Any], schema: Mapping[str, Any], where: str, errors: list[str]
) -> None:
    properties = schema.get("properties", {})
    if not isinstance(properties, Mapping):
        errors.append(f"{where}: 'properties' must be an object")
        return
    for key in schema.get("required", []):
        if key not in instance:
            errors.append(f"{where}: missing required property {key!r}")
    if schema.get("additionalProperties") is False:
        for key in instance:
            if key not in properties:
                errors.append(f"{where}: unknown property {key!r}")
    for key, value in instance.items():
        if key in properties:
            _validate(value, properties[key], f"{where}.{key}", errors)
