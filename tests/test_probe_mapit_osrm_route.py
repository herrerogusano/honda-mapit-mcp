from scripts import probe_mapit_osrm_route as probe


def detail(lines=2, points=2, *, inferred=False, point=False):
    features = [{"type": "Feature", "properties": {"inferred": inferred}, "geometry": {
        "type": "LineString", "coordinates": [[2.1 + i * .0001, 41.3, 99] for i in range(points)],
    }} for _ in range(lines)]
    if point:
        features.insert(1, {"type": "Feature", "geometry": {"type": "Point", "coordinates": [2.11, 41.31]}})
    return {"geoJSON": {"type": "FeatureCollection", "features": features}}


def match(points=2, confidence=.9):
    return {"code": "Ok", "matchings": [{"confidence": confidence, "legs": []}],
            "tracepoints": [{"matchings_index": 0} for _ in range(points)]}


def test_all_lines_checked_but_not_whole_route_claim():
    calls = []
    result = probe.assess_route(detail(point=True), transport=lambda *args: calls.append(args) or match())
    assert len(calls) == 2
    assert result["category"] == "matched_lines"
    assert result["tracepoint_coverage"] == "all"
    assert result["source_inferred_class"] == "all_false"
    assert result["excluded_point_features"]
    assert not result["whole_route_claim"]
    assert set(result) == probe.OUTPUT_KEYS


def test_global_limit_preflight_makes_no_calls():
    for payload in (detail(lines=9), detail(points=501), detail(lines=5, points=500)):
        calls = []
        result = probe.assess_route(payload, transport=lambda *args: calls.append(args))
        assert result["category"] == "resource_limit"
        assert not calls


def test_cardinality_mismatch_is_not_all_matched():
    result = probe.assess_route(detail(), transport=lambda *args: match(points=1))
    assert result["category"] == "invalid_input"
    assert not result["whole_route_claim"]


def test_null_tracepoints_are_partial():
    payload = match()
    payload["tracepoints"][0] = None
    result = probe.assess_route(detail(), transport=lambda *args: payload)
    assert result["category"] == "partial_lines"


def test_invalid_later_feature_prevents_all_network():
    payload = detail()
    payload["geoJSON"]["features"][1]["geometry"]["coordinates"][0][0] = 3
    calls = []
    result = probe.assess_route(payload, transport=lambda *args: calls.append(args))
    assert result["stage_category"] == "outside_bbox"
    assert not calls


def test_missing_inferred_is_not_false():
    payload = detail()
    payload["geoJSON"]["features"][1]["properties"].pop("inferred")
    result = probe.assess_route(payload, transport=lambda *args: match())
    assert result["source_inferred_class"] == "unknown"
    assert result["inferred_flag_availability"] == "partial"
