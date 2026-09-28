import json
from pathlib import Path

from mapit.anonymizer import schema_only


def test_schema_only_discards_values_lengths_counts_and_sensitive_dynamic_keys():
    raw = {
        "name": "Alice Example",
        "email": "alice@example.test",
        "vehicle": {
            "registration": "1234-ABC",
            "vin": "1HGCM82633A004352",
            "imei": "490154203237518",
            "lat": 40.4168,
            "lng": -3.7038,
            "timestamp": "2026-09-23T14:00:00Z",
        },
        "vehicles": [{"id": "vehicle-secret-1234567890", "battery": 87}, None],
        "alice@example.test": "secret-value",
        "550e8400-e29b-41d4-a716-446655440000": "uuid-value",
        "1234567890abcdef": "opaque-value",
        "token": "token-value",
    }
    schema = schema_only(raw)
    rendered = json.dumps(schema, sort_keys=True)
    for secret in (
        "Alice Example", "alice@example.test", "1234-ABC", "1HGCM82633A004352",
        "490154203237518", "40.4168", "-3.7038", "2026-09-23T14:00:00Z",
        "vehicle-secret-1234567890", "secret-value", "uuid-value", "opaque-value", "token-value",
    ):
        assert secret not in rendered
    assert schema["type"] == "object"
    assert schema["fields"]["vehicle"]["fields"]["lat"]["type"] == "number"
    assert schema["fields"]["vehicles"]["items"]["nullable"] is True
    assert "<email>" in schema["fields"]
    assert "<uuid>" in schema["fields"]
    assert "<id>" in schema["fields"]
    assert "<token>" in schema["fields"]
    assert "length" not in rendered and "example" not in rendered and "count" not in rendered


def test_schema_only_merges_array_shapes_and_nullability_without_cardinality():
    schema = schema_only([{"value": 1, "optional": None}, {"value": "text", "optional": True}])
    assert schema == {
        "type": "array",
        "nullable": False,
        "items": {
            "type": "object",
            "nullable": False,
            "fields": {
                "optional": {"type": "boolean", "nullable": True},
                "value": {"type": "mixed", "types": ["number", "string"], "nullable": False},
            },
        },
    }
    assert "2" not in json.dumps(schema)


def test_schema_only_neutralizes_short_and_tenant_style_dynamic_keys():
    schema = schema_only({
        "account-abc123": "account-secret",
        "eu-west-1:abc123": "identity-secret",
        "id1": "short-id-secret",
        "1234-ABC": "registration-secret",
        "status": "ordinary-field",
    })
    fields = schema["fields"]
    assert list(key for key in fields if key == "<id>") == ["<id>"]
    assert "account-abc123" not in fields
    assert "eu-west-1:abc123" not in fields
    assert "id1" not in fields
    assert "1234-ABC" not in fields
    assert "status" in fields


def test_schema_only_merges_heterogeneous_objects_with_one_sided_fields():
    raw = [
        {"only_left": "left-secret", "mixed": None, "nested": {"left_nested": 1}},
        {"only_right": "right-secret", "mixed": 7, "nested": {"right_nested": "value-secret"}},
    ]
    schema = schema_only(raw)
    rendered = json.dumps(schema, sort_keys=True)
    assert "left-secret" not in rendered
    assert "right-secret" not in rendered
    assert "value-secret" not in rendered
    fields = schema["items"]["fields"]
    assert fields["only_left"] == {"type": "string", "nullable": False}
    assert fields["only_right"] == {"type": "string", "nullable": False}
    assert fields["mixed"] == {"type": "number", "nullable": True}
    assert fields["nested"]["type"] == "object"
    assert set(fields["nested"]["fields"]) == {"left_nested", "right_nested"}


def test_schema_only_merges_null_and_type_changes_without_values_or_counts():
    schema = schema_only([
        {"field": None},
        {"field": "secret-value"},
        {"field": 42},
        {"field": True},
    ])
    assert schema["items"]["fields"]["field"] == {
        "type": "mixed",
        "types": ["boolean", "number", "string"],
        "nullable": True,
    }
    rendered = json.dumps(schema, sort_keys=True)
    assert "secret-value" not in rendered
    assert "42" not in rendered
    assert "count" not in rendered and "length" not in rendered


def test_schema_only_preserves_types_when_mixed_nodes_are_merged_successively():
    schema = schema_only([{"coordinates": [[1.0, 2.0], 3.0]}, {"coordinates": 4.0}])
    node = schema["items"]["fields"]["coordinates"]
    assert node == {"type": "mixed", "types": ["array", "number"], "nullable": False}
    rendered = json.dumps(schema, sort_keys=True)
    assert "1.0" not in rendered and "4.0" not in rendered


def test_routes_fixture_coordinates_mixed_node_matches_anonymizer_output():
    raw = {"data": [{"geoJSON": {"features": [{"geometry": {"coordinates": [[1.0, 2.0], 3.0]}}]}}]}
    generated = schema_only(raw)
    generated_node = generated["fields"]["data"]["items"]["fields"]["geoJSON"]["fields"]["features"]["items"]["fields"]["geometry"]["fields"]["coordinates"]["items"]
    expected = {"type": "mixed", "types": ["array", "number"], "nullable": False}
    assert generated_node == expected

    fixture_path = Path(__file__).parents[1] / "samples" / "anonymized" / "routes-list.schema.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    fixture_node = fixture["fields"]["data"]["items"]["fields"]["geoJSON"]["fields"]["features"]["items"]["fields"]["geometry"]["fields"]["coordinates"]["items"]
    assert fixture_node == expected
