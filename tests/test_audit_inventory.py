from types import SimpleNamespace

import pytest

from scripts.export_audit_requirements import installed_pins


def dist(name, version="1.0"):
    return SimpleNamespace(metadata={"Name": name}, version=version)


def test_only_first_party_is_excluded_and_third_party_pins_are_sorted():
    assert installed_pins([dist("mapit_client"), dist("Some_Package", "2.0"), dist("pip", "26.2")]) == (
        "pip==26.2", "some-package==2.0",
    )


@pytest.mark.parametrize("packages", [
    [], [dist("pip")], [dist("mapit-client")],
    [dist("mapit-client"), dist("bad\n--index-url")],
    [dist("mapit-client"), dist("pip", "file:///private-path")],
    [dist("mapit-client"), dist("pip", "1"), dist("pip", "2")],
    [dist("mapit-client")] + [dist("pip")] * 200,
])
def test_invalid_or_ambiguous_inventory_is_rejected(packages):
    with pytest.raises(ValueError):
        installed_pins(packages)
