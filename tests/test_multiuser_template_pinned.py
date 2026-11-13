"""The invitation-only multiuser templates must not change while the public
web mode is built: their canonical JSON is pinned byte for byte.

Pinned on b088168. If a change to these templates is intended, it belongs in
its own reviewed PR that updates these digests on purpose.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from scripts import build_multiuser_stack as stack

PINNED = {
    ("multiuser", "dev"): "a03b420bdc2167f64a30e37ec77af23c9301c0824dfefe5d9912dd2699cb5b0c",
    ("multiuser", "prod"): "d90cc6c8cf05d0c34e6ef3427342a4abc8f2b9bf8708384b5b3f0326b4939553",
    ("artifacts", "dev"): "202272c298b6f2956efee2f0158cd2fc9e48d590ad26185097f7aed5db43cfc7",
    ("artifacts", "prod"): "72495a72855cef066c85377270241d4fbd25bdac8bbf4d11f160376978bf3fc7",
}
BUILDERS = {"multiuser": stack.build_multiuser_template, "artifacts": stack.build_artifacts_template}


def _digest(template) -> str:
    canonical = json.dumps(template, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


@pytest.mark.parametrize(("kind", "env"), sorted(PINNED))
def test_invitation_templates_are_unchanged(kind, env):
    assert _digest(BUILDERS[kind](env)) == PINNED[(kind, env)]


def test_pin_detects_a_one_value_change(monkeypatch):
    # The gate itself: one changed value in the template changes the digest.
    monkeypatch.setattr(stack, "LOG_RETENTION_DAYS", stack.LOG_RETENTION_DAYS + 1)
    assert _digest(stack.build_multiuser_template("prod")) != PINNED[("multiuser", "prod")]


def test_templates_do_not_mention_the_public_web_mode():
    # Note: the invitation stack's web Cognito app client is already named
    # "honda-mapit-mcp-{env}-web"; that is a client name inside its own pool,
    # not a stack, table or parameter, so only those namespaces are checked.
    for kind, env in PINNED:
        text = json.dumps(BUILDERS[kind](env))
        assert "MAPIT_WEB_MODE" not in text
        assert f"honda-mapit-mcp-{env}-web-" not in text
        assert f"/honda-mapit-mcp/{env}/web/" not in text
