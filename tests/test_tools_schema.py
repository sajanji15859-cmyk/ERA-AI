"""Tests for the JSON-schema-subset validator (era.tools.schema)."""

from __future__ import annotations

from era.tools.schema import validate_schema


def object_schema(properties: dict, required: list | None = None) -> dict:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


class TestTypes:
    def test_valid_object_passes(self) -> None:
        schema = object_schema({"name": {"type": "string"}})
        assert validate_schema({"name": "x"}, schema) == []

    @staticmethod
    def _one_prop_schema(prop_type: str) -> dict:
        return object_schema({"value": {"type": prop_type}})

    def test_string(self) -> None:
        assert validate_schema({"value": "hi"}, self._one_prop_schema("string")) == []
        assert validate_schema({"value": 3}, self._one_prop_schema("string"))

    def test_integer_rejects_float_and_bool(self) -> None:
        assert validate_schema({"value": 3}, self._one_prop_schema("integer")) == []
        assert validate_schema({"value": 3.5}, self._one_prop_schema("integer"))
        assert validate_schema({"value": True}, self._one_prop_schema("integer"))

    def test_number_accepts_int_and_float_rejects_bool(self) -> None:
        assert validate_schema({"value": 2}, self._one_prop_schema("number")) == []
        assert validate_schema({"value": 2.5}, self._one_prop_schema("number")) == []
        assert validate_schema({"value": False}, self._one_prop_schema("number"))

    def test_boolean(self) -> None:
        assert validate_schema({"value": True}, self._one_prop_schema("boolean")) == []
        assert validate_schema({"value": "true"}, self._one_prop_schema("boolean"))

    def test_array_with_items(self) -> None:
        schema = object_schema({"tags": {"type": "array", "items": {"type": "string"}}})
        assert validate_schema({"tags": ["a", "b"]}, schema) == []
        assert validate_schema({"tags": ["a", 1]}, schema)
        assert validate_schema({"tags": "a"}, schema)

    def test_unsupported_type_fails_closed(self) -> None:
        errors = validate_schema({"value": 1}, object_schema({"value": {"type": "anyType"}}))
        assert any("unsupported type" in e for e in errors)


class TestConstraints:
    def test_required_missing(self) -> None:
        schema = object_schema({"a": {"type": "string"}}, required=["a"])
        errors = validate_schema({}, schema)
        assert any("missing required property 'a'" in e for e in errors)

    def test_unknown_property_rejected(self) -> None:
        schema = object_schema({"a": {"type": "string"}})
        errors = validate_schema({"a": "x", "evil": 1}, schema)
        assert any("unknown property 'evil'" in e for e in errors)

    def test_string_length_bounds(self) -> None:
        schema = object_schema({"s": {"type": "string", "minLength": 2, "maxLength": 4}})
        assert validate_schema({"s": "abc"}, schema) == []
        assert validate_schema({"s": "a"}, schema)
        assert validate_schema({"s": "abcde"}, schema)

    def test_number_bounds(self) -> None:
        schema = object_schema({"n": {"type": "integer", "minimum": 1, "maximum": 10}})
        assert validate_schema({"n": 5}, schema) == []
        assert validate_schema({"n": 0}, schema)
        assert validate_schema({"n": 11}, schema)

    def test_enum(self) -> None:
        schema = object_schema({"mode": {"type": "string", "enum": ["fast", "slow"]}})
        assert validate_schema({"mode": "fast"}, schema) == []
        assert validate_schema({"mode": "warp"}, schema)

    def test_nested_object(self) -> None:
        schema = object_schema(
            {
                "inner": {
                    "type": "object",
                    "properties": {"x": {"type": "integer"}},
                    "required": ["x"],
                }
            }
        )
        assert validate_schema({"inner": {"x": 1}}, schema) == []
        errors = validate_schema({"inner": {}}, schema)
        assert any("missing required property 'x'" in e for e in errors)

    def test_errors_accumulate(self) -> None:
        schema = object_schema({"a": {"type": "string"}, "b": {"type": "integer"}}, required=["b"])
        errors = validate_schema({"a": 1}, schema)
        assert len(errors) == 2
