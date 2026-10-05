"""Independent bounded checks for the public IGN Menorca boundary prototype."""

from __future__ import annotations

import re
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("defusedxml")
pytest.importorskip("pyproj")
pytest.importorskip("shapely")

from pyproj import network

from scripts import inspect_ign_menorca_boundary as boundary


SOURCE = Path(__file__).parents[1] / "samples" / "public-boundaries" / "menorca-ign-20261003.gml"
EXPECTED_CODES = {
    "34040707002",
    "34040707015",
    "34040707064",
    "34040707037",
    "34040707902",
    "34040707023",
    "34040707032",
    "34040707052",
}


@pytest.fixture(scope="module")
def public_gml() -> bytes:
    size = SOURCE.stat().st_size
    assert 0 < size <= boundary.MAX_SOURCE_BYTES
    data = SOURCE.read_bytes()
    assert len(data) == size
    return data


def test_checked_in_ign_extract_has_expected_union_and_only_expected_units(public_gml: bytes) -> None:
    features, report = boundary._read_features(public_gml)
    assert {item["properties"]["nationalCode"] for item in features} == EXPECTED_CODES
    assert report["feature_count"] == 8
    assert report["polygon_part_count"] == 111
    assert report["ring_count"] == 111
    assert report["vertex_count"] == 24_750
    assert report["edge_count"] == 24_639
    assert report["union_valid"] is True
    assert report["union_geometry_type"] == "MultiPolygon"
    assert report["transform_accuracy_m"] == 1.0
    assert report["union"].is_valid


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (lambda b: b.replace(b"<wfs:FeatureCollection", b'<!DOCTYPE x [<!ENTITY e "blocked">]><wfs:FeatureCollection', 1), "xml_declaration_forbidden"),
        (lambda b: b.replace(b"<au:nationalCode>34040707002</au:nationalCode>", b"<au:nationalCode>34040707099</au:nationalCode>", 1), "unexpected_national_code"),
        (
            lambda b: re.sub(
                rb'(<gml:MultiSurface[^>]*srsName=")[^"]+',
                rb'\g<1>http://www.opengis.net/def/crs/EPSG/0/4326',
                b,
                count=1,
            ),
            "unexpected_geometry_crs",
        ),
        (lambda b: b.replace(b"<gml:LinearRing>", b'<gml:LinearRing srsDimension="3">', 1), "unsupported_coordinate_dimension"),
        (
            lambda b: re.sub(rb"(<gml:posList>)[-0-9.]", rb"\g<1>oops", b, count=1),
            "invalid_coordinate_number",
        ),
    ],
)
def test_malformed_or_mismatched_public_gml_fails_closed(
    public_gml: bytes, mutate, expected_code: str
) -> None:
    corrupted = mutate(public_gml)
    assert corrupted != public_gml
    with pytest.raises(boundary.BoundaryError, match=f"^{expected_code}$"):
        boundary._read_features(corrupted)


def test_transformer_is_constructed_with_proj_network_disabled(public_gml: bytes, monkeypatch) -> None:
    previous = network.is_network_enabled()
    network.set_network_enabled(True)
    original = boundary.Transformer.from_crs

    def guarded_from_crs(*args, **kwargs):
        assert network.is_network_enabled() is False
        return original(*args, **kwargs)

    monkeypatch.setattr(boundary.Transformer, "from_crs", guarded_from_crs)
    try:
        boundary._read_features(public_gml)
    finally:
        network.set_network_enabled(previous)


def test_cli_reads_at_most_source_limit_plus_one_before_rejecting(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    source = tmp_path / "oversized.gml"
    source.write_bytes(b"x" * (boundary.MAX_SOURCE_BYTES + 1))
    output = tmp_path / "result.geojson"
    real_open = Path.open
    real_lstat = Path.lstat
    read_sizes: list[int] = []

    class GuardedReader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self, size=-1):
            read_sizes.append(size)
            assert 0 <= size <= boundary.MAX_SOURCE_BYTES + 1
            return self.stream.read(size)

    def guarded_open(path, *args, **kwargs):
        stream = real_open(path, *args, **kwargs)
        return GuardedReader(stream) if Path(path) == source else stream

    def underreported_lstat(path):
        result = real_lstat(path)
        if Path(path) == source:
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=boundary.MAX_SOURCE_BYTES)
        return result

    monkeypatch.setattr(Path, "open", guarded_open)
    monkeypatch.setattr(Path, "lstat", underreported_lstat)
    monkeypatch.setattr(sys, "argv", ["inspect_ign_menorca_boundary", "--input", str(source), "--output", str(output)])
    assert boundary.main() == 2
    assert read_sizes == [boundary.MAX_SOURCE_BYTES + 1]
    assert not output.exists()
    assert "source_byte_limit" in capsys.readouterr().err


def test_cli_does_not_overwrite_an_existing_output(public_gml: bytes, tmp_path: Path, monkeypatch, capsys) -> None:
    source = tmp_path / "source.gml"
    source.write_bytes(public_gml)
    output = tmp_path / "existing.geojson"
    output.write_bytes(b"keep-existing-content")
    monkeypatch.setattr(sys, "argv", ["inspect_ign_menorca_boundary", "--input", str(source), "--output", str(output)])
    assert boundary.main() == 2
    assert output.read_bytes() == b"keep-existing-content"
    assert "output_exists" in capsys.readouterr().err
