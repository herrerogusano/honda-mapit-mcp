# Managed Login cookie-clear hypothesis

Status: offline helper only; no live cause has been established.

The implementation delegates parsing, `Max-Age`, `Expires`, deletion, domain,
path, and `Secure` handling to Python's bounded in-memory
`http.cookiejar.CookieJar` and `DefaultCookiePolicy` ([Python standard-library
documentation](https://docs.python.org/3.10/library/http.cookiejar.html)).
RFC 6265 permits an empty cookie value; an empty value is therefore not itself
a deletion. A non-positive `Max-Age` or an expiry in the past is the deletion
signal ([RFC 6265, section 4.1.2.2](https://www.rfc-editor.org/rfc/rfc6265#section-4.1.2.2)).

`BoundedCookieStore` in `scripts/dev_multiuser_cookie_policy.py` remains
memory-only and adds the probe-specific bounds: at most 32 `Set-Cookie`
headers/cookies, at most 4 KiB per header/value, a 16 KiB outgoing Cookie
header, rejection of control characters, and an exact owned HTTPS host. It
does not persist cookies,
use proxies, follow redirects, log raw headers, or accept a cross-host cookie.
Native `CookieJar` rejection/ignoring of a foreign-domain update is preserved;
such a cookie is never stored or sent.
Invalid native input is surfaced only as the allowlisted `cookie_invalid`
diagnostic category; raw header contents are not included in errors.

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
