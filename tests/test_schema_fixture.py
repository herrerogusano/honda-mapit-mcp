import json
import re
from pathlib import Path

import pytest

SAMPLES_DIR = Path(__file__).parents[1] / "samples" / "anonymized"
SCHEMA_PATHS = [
    SAMPLES_DIR / "account-summary.schema.json",
    SAMPLES_DIR / "routes-list.schema.json",
    SAMPLES_DIR / "vehicle-detail.schema.json",
]
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
    node_type = node["type"]
    if node_type == "object":
        fields = node.get("fields")
        assert isinstance(fields, dict)
        for name, child in fields.items():
            assert isinstance(name, str)
            assert not SENSITIVE_FIELD.search(name)
            _validate_node(child)
        assert "items" not in node and "types" not in node
    elif node_type == "array":
        assert "items" in node and "fields" not in node
        assert "types" not in node
        _validate_node(node["items"])
    else:
        assert "fields" not in node and "items" not in node
    if "types" in node:
        assert node_type == "mixed"
        assert isinstance(node["types"], list)
        assert all(isinstance(item, str) and item in TYPES for item in node["types"])
    elif node_type == "mixed":
        assert False, "mixed nodes must declare their allowed types"


@pytest.mark.parametrize("schema_path", SCHEMA_PATHS, ids=lambda path: path.name)
def test_committed_schema_fixtures_are_value_free_and_structural_only(schema_path: Path):
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    _validate_node(schema)
