"""The invitation-only multiuser templates must not change while the public
web mode is built: the exact bytes sent as ``TemplateBody`` are pinned.

The digest is taken over the same serialization ``scripts/deploy_multiuser.py``
sends (``json.dumps(template, separators=(",", ":"))``, no ``sort_keys``), so a
reordered key also counts as a change. Pinned on b088168. If a change to these
templates is intended, it belongs in its own reviewed PR that updates these
digests on purpose.
"""

from __future__ import annotations

import hashlib
import inspect
import json

import pytest

from scripts import build_multiuser_stack as stack
from scripts import deploy_multiuser

PINNED = {
    ("multiuser", "dev"): "b4f7627320a12c6eb7b967657ff3cc0f1741a4f4ebfe01962b8b775fdc8a846a",
    ("multiuser", "prod"): "b509ae655aeb21680e8697ac6b6e5e788d4bde87bfcea13a1e7606e0f26e9985",
    ("artifacts", "dev"): "ec74cdf9dbc9e96c7288ee4300ad5c4f3b73aa36b579bc0db0762471a7da3ac1",
    ("artifacts", "prod"): "b661f02848d9b0e4024a0540b1bffe47a339838e4c10a368903e4c71b69e08ff",
}
BUILDERS = {"multiuser": stack.build_multiuser_template, "artifacts": stack.build_artifacts_template}
DEPLOY_SERIALIZATION = 'TemplateBody=json.dumps(template, separators=(",", ":")),'


def _template_body(template) -> str:
    return json.dumps(template, separators=(",", ":"))


def _digest(template) -> str:
    return hashlib.sha256(_template_body(template).encode("utf-8")).hexdigest()


@pytest.mark.parametrize(("kind", "env"), sorted(PINNED))
def test_invitation_templates_are_unchanged(kind, env):
    assert _digest(BUILDERS[kind](env)) == PINNED[(kind, env)]


def test_pin_uses_the_deploy_serialization():
    # If the deploy script changes how it serializes TemplateBody, re-pin here.
    assert inspect.getsource(deploy_multiuser).count(DEPLOY_SERIALIZATION) == 1


def test_pin_detects_a_one_value_change(monkeypatch):
    # The gate itself: one changed value in the template changes the digest.
    monkeypatch.setattr(stack, "LOG_RETENTION_DAYS", stack.LOG_RETENTION_DAYS + 1)
    assert _digest(stack.build_multiuser_template("prod")) != PINNED[("multiuser", "prod")]


def test_pin_detects_reordered_keys():
    template = stack.build_multiuser_template("prod")
    template["Resources"] = dict(reversed(list(template["Resources"].items())))
    assert _digest(template) != PINNED[("multiuser", "prod")]


def test_templates_do_not_mention_the_public_web_mode():
    # Note: the invitation stack's web Cognito app client is already named
    # "honda-mapit-mcp-{env}-web"; that is a client name inside its own pool,
    # not a stack, table or parameter, so only those namespaces are checked.
    for kind, env in PINNED:
        text = json.dumps(BUILDERS[kind](env))
        assert "MAPIT_WEB_MODE" not in text
        assert f"honda-mapit-mcp-{env}-web-" not in text
        assert f"/honda-mapit-mcp/{env}/web/" not in text
