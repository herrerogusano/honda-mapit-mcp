import json
import re
from pathlib import Path


SCHEMA_PATH = Path(__file__).parents[1] / "samples" / "anonymized" / "account-summary.schema.json"
ALLOWED_KEYS = {"type", "nullable", "fields", "items", "types"}
TYPES = {"object", "array", "string", "number", "boolean", "null", "unknown", "mixed"}
SENSITIVE_FIELD = re.compile(
    r"(?:@|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$|^[0-9A-HJKMNP-TV-Z]{17}$)",
    re.I,
)


def _validate_node(node: object) -> None:
    assert isinstance(node, dict)
    assert set(node) <= ALLOWED_KEYS
    assert isinstance(node.get("type"), str) and node["type"] in TYPES
    assert isinstance(node.get("nullable"), bool)
    if node["type"] == "object":
        fields = node.get("fields")
        assert isinstance(fields, dict)
        for name, child in fields.items():
            assert isinstance(name, str)
            assert not SENSITIVE_FIELD.search(name)
            _validate_node(child)
    elif node["type"] == "array":
        _validate_node(node["items"])
    if "types" in node:
        assert node["type"] == "mixed"
        assert isinstance(node["types"], list)
        assert all(isinstance(item, str) and item in TYPES for item in node["types"])


def test_committed_schema_fixture_is_value_free_and_structural_only():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    _validate_node(schema)

