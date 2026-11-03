import json
import subprocess
import sys
from pathlib import Path

import pytest

from orbit_ir.schema import load_schema, schema_json


def test_schema_loads_as_valid_json():
    schema = load_schema()
    assert schema["$schema"] == "https://json-schema.org/draft-07/schema#"
    assert schema["type"] == "object"
    assert "properties" in schema
    assert "required" in schema


def test_schema_json_is_valid_json_string():
    text = schema_json()
    parsed = json.loads(text)
    assert parsed["title"] == "ORBIT Analysis Summary"


def test_schema_required_fields():
    schema = load_schema()
    required = schema["required"]
    assert "synthetic" in required
    assert "corpus" in required
    assert "findings" in required
    assert "method" in required
    assert "limitations" in required
    assert "runtime_seconds" in required


def test_schema_defs_cover_subobjects():
    schema = load_schema()
    defs = schema.get("$defs", {})
    assert "corpus" in defs
    assert "findings_summary" in defs
    assert "method" in defs
    assert "evaluation" in defs
    assert "prf" in defs
    assert "finding" in defs
    assert "trajectory" in defs


def test_demo_output_matches_schema_structurally(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "orbit_ir.cli", "demo", "--workdir", str(tmp_path)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    schema = load_schema()
    _validate_against_schema(summary, schema, "root")


def test_schema_cli_command():
    result = subprocess.run(
        [sys.executable, "-m", "orbit_ir.cli", "schema"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    parsed = json.loads(result.stdout)
    assert parsed["title"] == "ORBIT Analysis Summary"


def _validate_against_schema(data, schema, path):
    """Structural validation of data against a JSON Schema without jsonschema."""
    resolved = schema
    if "$ref" in resolved:
        ref = resolved["$ref"]
        assert ref.startswith("#/$defs/"), f"unsupported $ref: {ref}"
        def_name = ref.split("/")[-1]
        root = load_schema()
        resolved = root["$defs"][def_name]

    expected_type = resolved.get("type")
    if expected_type == "object":
        assert isinstance(data, dict), f"{path}: expected object, got {type(data).__name__}"
        for field in resolved.get("required", []):
            assert field in data, f"{path}: missing required field '{field}'"
        props = resolved.get("properties", {})
        for key, prop_schema in props.items():
            if key in data:
                _validate_against_schema(data[key], prop_schema, f"{path}.{key}")
    elif expected_type == "array":
        assert isinstance(data, list), f"{path}: expected array, got {type(data).__name__}"
        item_schema = resolved.get("items")
        if item_schema and data:
            _validate_against_schema(data[0], item_schema, f"{path}[0]")
    elif expected_type == "string":
        assert isinstance(data, str), f"{path}: expected string, got {type(data).__name__}"
        enum_values = resolved.get("enum")
        if enum_values:
            assert data in enum_values, f"{path}: '{data}' not in {enum_values}"
    elif expected_type == "integer":
        assert isinstance(data, int), f"{path}: expected integer, got {type(data).__name__}"
    elif expected_type == "number":
        assert isinstance(data, (int, float)), f"{path}: expected number, got {type(data).__name__}"
    elif expected_type == "boolean":
        assert isinstance(data, bool), f"{path}: expected boolean, got {type(data).__name__}"
    elif isinstance(expected_type, list):
        type_map = {"string": str, "null": type(None), "integer": int, "number": (int, float), "boolean": bool}
        allowed = tuple(type_map[t] for t in expected_type if t in type_map)
        assert isinstance(data, allowed) or data is None, f"{path}: type {type(data).__name__} not in {expected_type}"
