# Managed Login cookie-clear hypothesis

Status: offline helper only; no live cause has been established.

The deletion rule follows RFC 6265's `Max-Age` semantics: a non-positive
`Max-Age` makes the cookie immediately stale. This helper uses only that
explicit signal and does not interpret `Expires`, so it never depends on a
local wall clock. See the [RFC 6265 cookie specification](https://www.rfc-editor.org/rfc/rfc6265#section-4.1.2.2).

The private direct probe currently rejects an empty `Set-Cookie` value. A
redirect may legitimately clear an existing session cookie with an explicit
non-positive `Max-Age`. The isolated helper in
`scripts/dev_multiuser_cookie_policy.py` accepts only that narrow form, only
for a cookie already present in the in-memory jar, and removes it. Empty
unknown cookies, empty cookies without `Max-Age`, malformed `Max-Age`, and
expiry-only deletion remain fail-closed. It performs no wall-clock parsing.

The helper is not evidence that Cognito sent such a header in the failed run.
The bounded audit observed `login_POST` and two authorization events but no
token event; the raw response headers were intentionally not retained. AWS
documents Managed Login browser cookies and session clearing, while its
Managed Login pages are browser-facing rather than a stable programmatic API.
Live retry uses the approved direct technical probe while the exact form and
redirect contract remains stable, and requires the reviewed browser fallback
only if the unsupported Managed Login HTML/redirect surface drifts. The
owner-authorized same-user recovery contract remains mandatory for a new
password because the previous password was discarded.
