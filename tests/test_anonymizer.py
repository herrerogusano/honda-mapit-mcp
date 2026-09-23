import json

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
