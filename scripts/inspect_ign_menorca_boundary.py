"""Offline prototype: validate and convert one bounded public IGN GML extract.

This is a review utility, not runtime code. It performs no network or MAPIT
calls and prints only sanitized source/geometry metadata, never coordinates.
Requires defusedxml, pyproj, and Shapely in an explicitly selected environment.
"""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
import time
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as SafeET
from pyproj import CRS, Transformer, network
from pyproj.exceptions import ProjError
from shapely import prepare
from shapely.geometry import MultiPolygon, Point, Polygon, mapping
from shapely.ops import unary_union
from shapely.errors import GEOSException
from shapely.validation import explain_validity


MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_ELEMENTS = 100_000
MAX_DEPTH = 32
MAX_VERTICES = 35_000
EXPECTED_SOURCE_CRS = "http://www.opengis.net/def/crs/EPSG/0/4258"
EXPECTED_CODES = {
    "34040707002": "Alaior",
    "34040707015": "Ciutadella de Menorca",
    "34040707064": "es Castell",
    "34040707037": "Es Mercadal",
    "34040707902": "Es Migjorn Gran",
    "34040707023": "Ferreries",
    "34040707032": "Maó",
    "34040707052": "Sant Lluís",
}
NS = {
    "wfs": "http://www.opengis.net/wfs/2.0",
    "au": "http://inspire.ec.europa.eu/schemas/au/4.0",
    "gml": "http://www.opengis.net/gml/3.2",
}


class BoundaryError(ValueError):
    pass


class _CoordinateBudget:
    def __init__(self) -> None:
        self.vertices = 0


def _exact_child(node: Any, namespace: str, name: str) -> Any:
    found = node.find(f"{{{namespace}}}{name}")
    if found is None:
        raise BoundaryError("unexpected_gml_shape")
    return found


def _check_tree(root: Any) -> None:
    stack = [(root, 1)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_ELEMENTS or depth > MAX_DEPTH:
            raise BoundaryError("xml_structure_limit")
        stack.extend((child, depth + 1) for child in node)


def _check_coordinate_metadata(geometry: Any) -> None:
    for element in geometry.iter():
        for attribute, value in element.attrib.items():
            name = attribute.rsplit("}", 1)[-1]
            if name == "srsDimension" and value != "2":
                raise BoundaryError("unsupported_coordinate_dimension")
            if name in {"axisLabels", "uomLabels"}:
                raise BoundaryError("unexpected_coordinate_labels")


def _positions(
    pos_list: Any, transformer: Transformer, budget: _CoordinateBudget
) -> list[tuple[float, float]]:
    if pos_list.attrib.get("srsDimension") not in (None, "2"):
        raise BoundaryError("unsupported_coordinate_dimension")
    text = pos_list.text or ""
    raw = text.split()
    if len(raw) < 8 or len(raw) % 2:
        raise BoundaryError("invalid_ring_coordinate_count")
    vertex_count = len(raw) // 2
    if budget.vertices + vertex_count > MAX_VERTICES:
        raise BoundaryError("coordinate_limit")
    budget.vertices += vertex_count
    try:
        values = [float(value) for value in raw]
    except (ValueError, OverflowError):
        raise BoundaryError("invalid_coordinate_number") from None
    if any(not (value == value and abs(value) != float("inf")) for value in values):
        raise BoundaryError("invalid_coordinate_number")
    result: list[tuple[float, float]] = []
    # EPSG:4258 axis order is latitude, longitude; EPSG:4326 uses the same
    # authority axis order. RFC 7946 output is longitude, latitude.
    for latitude, longitude in zip(values[::2], values[1::2]):
        try:
            out_lat, out_lon = transformer.transform(latitude, longitude, errcheck=True)
        except ProjError:
            raise BoundaryError("transform_failed") from None
        if not (-90 <= out_lat <= 90 and -180 <= out_lon <= 180):
            raise BoundaryError("transformed_coordinate_out_of_range")
        result.append((out_lon, out_lat))
    if result[0] != result[-1]:
        raise BoundaryError("open_linear_ring")
    return result


def _read_features(source: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    transform_started = time.perf_counter()
    if len(source) > MAX_SOURCE_BYTES:
        raise BoundaryError("source_byte_limit")
    if re.search(br"<!\s*(DOCTYPE|ENTITY)\b", source, re.IGNORECASE):
        raise BoundaryError("xml_declaration_forbidden")
    try:
        root = SafeET.fromstring(source)
    except Exception as exc:
        raise BoundaryError("invalid_xml") from exc
    _check_tree(root)
    if root.tag != f"{{{NS['wfs']}}}FeatureCollection":
        raise BoundaryError("unexpected_root")
    timestamp = root.attrib.get("timeStamp")
    if not timestamp or root.attrib.get("numberMatched") != "8" or root.attrib.get("numberReturned") != "8":
        raise BoundaryError("unexpected_feature_collection_metadata")

    crs = CRS.from_epsg(4258)
    target = CRS.from_epsg(4326)
    src_axes = crs.axis_info
    dst_axes = target.axis_info
    if [axis.direction for axis in src_axes[:2]] != ["north", "east"]:
        raise BoundaryError("unexpected_source_axis_order")
    if [axis.direction for axis in dst_axes[:2]] != ["north", "east"]:
        raise BoundaryError("unexpected_target_axis_order")
    network.set_network_enabled(False)
    if network.is_network_enabled():
        raise BoundaryError("proj_network_not_disabled")
    try:
        transformer = Transformer.from_crs(
            crs,
            target,
            always_xy=False,
            allow_ballpark=False,
            only_best=True,
        )
    except ProjError:
        raise BoundaryError("transform_unavailable") from None
    if transformer.accuracy < 0 or transformer.accuracy > 1:
        raise BoundaryError("transform_accuracy_unverified")

    members = root.findall(f"{{{NS['wfs']}}}member")
    if len(members) != 8:
        raise BoundaryError("unexpected_member_count")
    features: list[dict[str, Any]] = []
    seen_codes: set[str] = set()
    ring_count = 0
    vertices_by_code: dict[str, int] = {}
    rings_by_code: dict[str, int] = {}
    polygons_for_union: list[Polygon] = []
    budget = _CoordinateBudget()

    for member in members:
        unit = _exact_child(member, NS["au"], "AdministrativeUnit")
        code = (_exact_child(unit, NS["au"], "nationalCode").text or "").strip()
        if code not in EXPECTED_CODES or code in seen_codes:
            raise BoundaryError("unexpected_national_code")
        seen_codes.add(code)
        feature_id = unit.attrib.get(f"{{{NS['gml']}}}id", "")
        if feature_id != f"AU_ADMINISTRATIVEUNIT_{code}":
            raise BoundaryError("unexpected_feature_id")
        geometry = _exact_child(unit, NS["au"], "geometry")
        multi_surface = _exact_child(geometry, NS["gml"], "MultiSurface")
        if multi_surface.attrib.get("srsName") != EXPECTED_SOURCE_CRS:
            raise BoundaryError("unexpected_geometry_crs")
        _check_coordinate_metadata(geometry)
        surface_members = multi_surface.findall(f"{{{NS['gml']}}}surfaceMember")
        if not surface_members:
            raise BoundaryError("empty_municipality_geometry")
        municipality_polygons: list[Polygon] = []
        local_vertices = 0
        local_rings = 0
        for surface_member in surface_members:
            polygon_node = _exact_child(surface_member, NS["gml"], "Polygon")
            exterior = _exact_child(polygon_node, NS["gml"], "exterior")
            exterior_pos = _exact_child(_exact_child(exterior, NS["gml"], "LinearRing"), NS["gml"], "posList")
            shell = _positions(exterior_pos, transformer, budget)
            local_rings += 1
            local_vertices += len(shell)
            holes: list[list[tuple[float, float]]] = []
            for interior in polygon_node.findall(f"{{{NS['gml']}}}interior"):
                pos = _exact_child(_exact_child(interior, NS["gml"], "LinearRing"), NS["gml"], "posList")
                hole = _positions(pos, transformer, budget)
                local_rings += 1
                local_vertices += len(hole)
                holes.append(hole)
            try:
                polygon = Polygon(shell, holes)
            except GEOSException:
                raise BoundaryError("geometry_construction_failed") from None
            if not polygon.is_valid or polygon.is_empty:
                raise BoundaryError("invalid_polygon")
            municipality_polygons.append(polygon)
            polygons_for_union.append(polygon)
        if len(municipality_polygons) == 1:
            municipality_geometry = municipality_polygons[0]
        else:
            municipality_geometry = MultiPolygon(municipality_polygons)
            if not municipality_geometry.is_valid:
                raise BoundaryError("invalid_multipolygon")

        name_node = _exact_child(unit, NS["au"], "name")
        name = "".join(name_node.itertext()).strip()
        if name != EXPECTED_CODES[code]:
            raise BoundaryError("unexpected_municipality_name")
        features.append(
            {
                "type": "Feature",
                "properties": {"nationalCode": code, "name": name},
                "geometry": mapping(municipality_geometry),
            }
        )
        vertices_by_code[code] = local_vertices
        rings_by_code[code] = local_rings
        ring_count += local_rings

    if seen_codes != set(EXPECTED_CODES):
        raise BoundaryError("missing_national_code")
    union_started = time.perf_counter()
    try:
        union = unary_union(polygons_for_union)
    except GEOSException:
        raise BoundaryError("geometry_union_failed") from None
    union_ms = (time.perf_counter() - union_started) * 1000
    if union.is_empty or not union.is_valid:
        raise BoundaryError("invalid_union")
    return features, {
        "source_timestamp": timestamp,
        "feature_count": len(features),
        "polygon_part_count": len(polygons_for_union),
        "ring_count": ring_count,
        "vertex_count": budget.vertices,
        "edge_count": budget.vertices - ring_count,
        "vertices_by_code": vertices_by_code,
        "rings_by_code": rings_by_code,
        "union_valid": bool(union.is_valid),
        "union_validity_reason": explain_validity(union),
        "union_geometry_type": union.geom_type,
        "transform_accuracy_m": transformer.accuracy,
        "transform_operation": transformer.description,
        "parse_transform_ms": round((time.perf_counter() - transform_started) * 1000, 3),
        "union_ms": round(union_ms, 3),
        "union": union,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.input.absolute() == args.output.absolute():
        parser.error("input and output must be different files")
    started = time.perf_counter()
    try:
        input_stat = args.input.lstat()
        if not stat.S_ISREG(input_stat.st_mode) or args.input.is_symlink():
            raise BoundaryError("input_not_regular_file")
        if input_stat.st_size > MAX_SOURCE_BYTES:
            raise BoundaryError("source_byte_limit")
        with args.input.open("rb") as source_file:
            source = source_file.read(MAX_SOURCE_BYTES + 1)
        if len(source) > MAX_SOURCE_BYTES:
            raise BoundaryError("source_byte_limit")
        features, report = _read_features(source)
    except BoundaryError as exc:
        code = str(exc)
        print(json.dumps({"status": "rejected", "category": code}), file=sys.stderr)
        return 2
    except OSError:
        code = "io_error"
        print(json.dumps({"status": "rejected", "category": code}), file=sys.stderr)
        return 2
    except (ProjError, GEOSException):
        code = "geometry_or_transform_failed"
        print(json.dumps({"status": "rejected", "category": code}), file=sys.stderr)
        return 2
    except Exception:
        code = "prototype_failed"
        print(json.dumps({"status": "rejected", "category": code}), file=sys.stderr)
        return 2

    collection = {"type": "FeatureCollection", "features": features}
    output = json.dumps(collection, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(output) > MAX_SOURCE_BYTES:
        print(json.dumps({"status": "rejected", "category": "output_byte_limit"}), file=sys.stderr)
        return 2
    try:
        with args.output.open("xb") as output_file:
            output_file.write(output)
    except FileExistsError:
        print(json.dumps({"status": "rejected", "category": "output_exists"}), file=sys.stderr)
        return 2
    except OSError:
        print(json.dumps({"status": "rejected", "category": "output_io_error"}), file=sys.stderr)
        return 2

    union = report.pop("union")
    prepare_start = time.perf_counter()
    prepare(union)
    prepare_ms = (time.perf_counter() - prepare_start) * 1000
    benchmark_point = union.representative_point()
    covers_start = time.perf_counter()
    try:
        covered_count = sum(bool(union.covers(benchmark_point)) for _ in range(1000))
    except GEOSException:
        print(json.dumps({"status": "rejected", "category": "geometry_predicate_failed"}), file=sys.stderr)
        return 2
    covers_1000_ms = (time.perf_counter() - covers_start) * 1000
    report.update(
        {
            "status": "accepted_for_review",
            "source_bytes": len(source),
            "output_bytes": len(output),
            "output_path": str(args.output),
            "union_prepare_ms": round(prepare_ms, 3),
            "synthetic_covers_1000_ms": round(covers_1000_ms, 3),
            "synthetic_covered": covered_count,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "benchmark_note": "same synthetic public-boundary interior point tested 1,000 times; not a runtime SLO",
        }
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
