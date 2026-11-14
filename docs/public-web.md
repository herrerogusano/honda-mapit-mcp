# Public web mode (technical contract)

The public web mode lets anyone with a MAPIT account sign in to the static web
client without an invitation, with a cap on distinct people and with every
session gone in less than one hour. It runs from the same code as the
invitation-only multiuser stack (`docs/multiuser-production.md`) and is enabled
only by the environment variable `MAPIT_WEB_MODE=public`, which that stack never
sets. With the variable absent, nothing in this document runs; any value other
than `public` is a configuration error (`web_mode_invalid`).

Claude and Codex are not clients of this stack: its user pool is separate, so a
token from it is never accepted by the invitation-only API, and vice versa.

Source of truth for every value below: `src/mapit/public_web.py` (names, limits,
rows), `src/mapit/public_identity.py` (sign-in), `src/mapit/public_pass.py`
(pre-login pass), `src/mapit/public_web_service.py` (`/mcp` gate),
`src/mapit/public_sweep.py` (sweep) and `scripts/mcp_users_web.py` (operation
commands). If this document and the code disagree, the code wins and this
document has a bug.

## Resources and names

One CloudFormation stack per environment (`env` in `dev|prod`, region
eu-west-1). The template and its deployment are described in the template
script (planned name `scripts/build_web_stack.py`); this section lists only
the names the code depends on.

| Resource | Name |
|---|---|
| Stack | `honda-mapit-mcp-{env}-web` |
| User pool | `honda-mapit-mcp-{env}-web-users` (`public_sweep.web_user_pool_name`) |
| Table | `honda-mapit-mcp-{env}-web-state`, partition key `pk` (S), no sort key, TTL attribute `expires_at` |
| Functions | `honda-mapit-mcp-{env}-web-identity`, `-web-mcp`, `-web-pass`, `-web-sweep` |
| MAPIT session parameters | `/honda-mapit-mcp/{env}/web/sessions/<tenant id>/mapit-refresh-token` (SecureString) |
| Fingerprint key | `/honda-mapit-mcp/{env}/web/fingerprint-key` (SecureString, 32 random bytes, base64) |
| Turnstile secret | `/honda-mapit-mcp/{env}/web/turnstile-secret` (SecureString) |
| Sweep metrics | namespace `honda-mapit-mcp/web`, dimension `Environment` |

HTTP routes of the web API: `POST /pase` (pass function), `GET /estado`
(identity function, no authentication) and `POST /mcp` (service, JWT).

### Hard to undo

Changing any of these needs a new stack or resets data; check them against
this document before every stack creation:

- **User pool name and login domain**: a pool cannot be renamed. The sweep
  deletes users only in a pool with exactly the name above.
- **Table key**: `pk` as the only key, and every row key format below. A new
  key schema means a new table and loses every count.
- **Fingerprint format** (`public_web.py` docstring): HMAC-SHA256 over
  `honda-mapit-mcp/web/fingerprint/v1/` + domain + `\x00` + value, with the
  email normalized and IPv6 reduced to its /64. Changing it, or losing or
  recreating the key, resets every person and attempt row: everybody becomes
  "new" and seats are recounted. A key created after the first deployment
  logs the event `fingerprint_key_created`.

## Sign-in flow

1. **Pass.** The web shows a consent screen with an email field and a
   Cloudflare Turnstile check, then sends `POST /pase` with
   `{"email": ..., "turnstile": ...}`. The pass function:
   1. validates its environment and the exact JSON body;
   2. reads the source IP from the API event;
   3. reads the configuration row: closed or paused answers like `/estado`,
      without calling Cloudflare;
   4. calls Turnstile `siteverify` (2 s timeout) and checks `success`, the
      hostname (from `MAPIT_WEB_TURNSTILE_HOSTNAMES`) and the action
      `web-pass`; no answer or an odd answer means no pass;
   5. marks the result as used (conditional put on `result#<fp>`): a result
      gives at most one pass, even before Cloudflare detects the repeat;
   6. counts the pass for the IP (`ip#<fp>#<window>`, at most 5 per
      10-minute window);
   7. writes `pass#<email fp>` with 3 attempts and a 5-minute expiry. A new
      pass replaces the old one and resets its attempts.

   The answer is the same for every email: it never tells whether an email has
   used the web.
2. **Cognito login page.** The web redirects to the pool's managed login with
   the email prefilled (`login_hint`). The user types the MAPIT password there.
3. **Migration** (`UserMigration_Authentication`, user not in the pool). One
   consistent `BatchGetItem` of config, person, attempts, pass and the three
   breaker rows. Refusals that never call MAPIT, in this order: closed or
   paused, breaker open, email locked, no valid pass. Then one pass attempt is
   spent with a conditional decrement (of several racing migrations only one
   reaches MAPIT), one MAPIT login, and:
   - MAPIT rejects: one transaction adds to the attempts row (lock at the
     fifth failure), the breaker row and the day's `mapit_rejections`;
   - MAPIT accepts and the person is new while the cap is full: "no seats"
     (counted in `cap_rejections`); nothing is created. The cap is checked only
     after the password is proven, so the answer never reveals whether an
     email signed in before;
   - MAPIT accepts and the person reached 10 sign-ins today: daily limit;
   - otherwise: the MAPIT session is stored under a random tenant id, then one
     transaction writes the person row, the usage row and, for a new person,
     the seat (conditional on the cap) and the day's `new_people`.
4. **Pre-authentication** (`PreAuthentication_Authentication`, user still in
   the pool because it signed in less than about 50 minutes ago). The same
   refusals. Cognito checks the password against its own hash, so no migration
   runs and the pass attempt is spent here, unless a migration of the same
   email spent one in the last 10 seconds. For an absent user it only checks
   the pass.
5. **Token issue** (`TokenGeneration_*`). Refresh is refused. Every other issue
   counts one sign-in on the person row (at most 10 per UTC day) and on the
   day and month rows (`logins`), then adds the tenant claim.
6. **Calls.** Each `/mcp` tool call passes the session gate (below) before any
   MAPIT read. Only six tools exist: `get_vehicle_status`,
   `get_vehicle_details`, `list_routes`, `get_route_detail`, `cerrar_sesion`
   and `borrar_mis_datos`.

"Forgot password" never calls MAPIT and answers with a fixed text.

## Table rows

| Row (`pk`) | Holds | Lives |
|---|---|---|
| `config` | `open`, `pause_until`, `cap`, `occupied`, `pass_required` | No expiry |
| `person#<email fp>` | first and last sign-in, sign-in count and day count, consent version and date | 365 days after the last sign-in |
| `attempts#<email fp>` | failed MAPIT logins, `locked_until`; also for emails that never signed in | 24 hours |
| `pass#<email fp>` | `attempts_left`, `issued_at`, `migration_spent_at` | 5 minutes |
| `result#<result fp>` | marks a Turnstile result as used | 10 minutes |
| `ip#<ip fp>#<window>` | passes issued to one IP in one 10-minute window | until one window after its window ends |
| `breaker#<window>` | MAPIT rejections in one 10-minute window, `open_until` | 15 minutes plus one window after its window ends |
| `usage#<tenant id>` | `person_fp`, `login_at`, `calls`, per-minute counter `m<epoch minute>` | 2 hours |
| `day#YYYY-MM-DD` (UTC) | `logins`, `new_people`, `mapit_rejections`, `cap_rejections` | No expiry; counts only |
| `month#YYYY-MM` (UTC) | `logins` | No expiry; counts only |

DynamoDB TTL deletes expired rows late (typically within days), so every reader
treats `expires_at <= now` as absent. Outside the table: the Cognito user (less
than one hour), the MAPIT session parameter (less than one hour) and function
logs (retention set by the template; the code never logs emails, passwords,
tokens, IPs or fingerprints).

The configuration row accepts only the attributes listed above; an unknown
attribute, a wrong type or a wrong key closes the service (`malformed`). An
absent row means the defaults: open, no pause, cap 100, pass required. A failed
read also closes (`read_failed`). `occupied` is written only by the seat claim,
by `borrar_mis_datos` (which frees the seat) and by the sweep's daily recount
(03:00-03:05 UTC, set to the number of unexpired person rows, only if
`occupied` did not change during the count).

## Less than one hour

Five independent mechanisms:

1. **Sign-out deletes at once.** `cerrar_sesion` deletes the MAPIT session
   parameter, the Cognito user and the usage row. `borrar_mis_datos` also
   deletes the person row and frees its seat.
2. **Sweep every 5 minutes, by age.** It deletes session parameters whose
   `LastModifiedDate` and pool users whose `UserCreateDate` is 50 minutes or
   older, without reading values or knowing whose they are. It first checks
   with `DescribeUserPool` that the configured pool id is the pool with the
   expected name; otherwise it deletes nothing. Worst case: 55 minutes plus the
   run time.
3. **The service refuses old sessions.** Each call compares the token's
   `auth_time` and the usage row's `login_at` with 55 minutes; an older,
   missing or expired session is deleted on the spot and the call answers
   `session_expired`. This works even if the sweep fails.
4. **No refresh.** The identity function refuses refresh token issues, so an
   access token (60 minutes) cannot be extended.
5. **Alarm.** Each sweep run writes one EMF log line with
   `OldestItemAgeSeconds`, `SweepFailed` and `SweepIncomplete`. The alarms on
   them (oldest item at 60 minutes or more, a failed run) belong to the stack
   template.

A second sign-in within the same hour is cut early: the user created by the
first one keeps its creation date.

## Limits

| Limit | Value | Where |
|---|---|---|
| Distinct people (cap) | 100 by default; `cap = 0` means no cap | config row; checked atomically with the seat claim |
| Failed MAPIT logins per email | 5, then locked 15 minutes | attempts row |
| Circuit breaker | 20 MAPIT rejections in one 10-minute window close all sign-ins for 15 minutes | breaker rows |
| Calls per session | 80 | usage row |
| Calls per session and minute | 30 | usage row, `m<epoch minute>` |
| Sign-ins per person and UTC day | 10 | person row |
| Passes per IP | 5 per 10-minute window | `ip#` rows |
| Attempts per pass | 3, valid 5 minutes | pass row |
| Session age | 55 minutes in the service, 50 minutes in the sweep | |

## `/estado` vocabulary

`GET /estado` answers `{"estado": ...}` with `cache-control: no-store` and no
personal data. The same words are used by the pass endpoint and by
`web-status`.

| Value | Meaning |
|---|---|
| `abierto` | open, not paused, breaker closed, room left (or no cap) |
| `lleno` | open but the cap is reached; people who signed in before can still enter |
| `cerrado` | `open = false`: no sign-ins; sessions already open continue |
| `pausa` | `pause_until` in the future, breaker open, or a malformed configuration row (HTTP 200); a failed read (HTTP 503). A pause also stops every `/mcp` call |

## Error codes

Cognito login page (text shown above the form): bad credentials, start from
the web (no valid pass, or a different email typed), paused, no seats, daily
limit, too many attempts (locked), session ended (refresh refused), generic.
The log line of each refusal carries a fixed step code (for example
`pass_missing`, `breaker_open`, `locked`, `cap_full`, `mapit_rejected`,
`mapit_failed`), the exception class and the AWS error code only.

`POST /pase`:

| HTTP | Body | When |
|---|---|---|
| 200 | `{"pase": "emitido", "caduca_en_segundos": 300}` | pass written |
| 400 | `{"error": "peticion_invalida"}` | body or email invalid |
| 403 | `{"error": "control_no_valido"}` | Turnstile rejected or result already used |
| 404 | `{"error": "no_encontrado"}` | other route or method |
| 429 | `{"error": "demasiados_pases"}` | IP limit reached |
| 503 | `{"error": "no_disponible"}` | Cloudflare, SSM or the table did not answer (fails closed) |
| 503 | `{"estado": "cerrado"}` / `{"estado": "pausa"}` | as `/estado` |

`/mcp` tool errors are `"<code>: <message>"` with the code one of
`session_expired`, `session_limit_reached`, `rate_limited`, `service_paused`,
`service_unavailable`, `logout_failed`, `delete_failed`.

## Operation commands

All in `scripts/mcp_users.py` (implemented in `scripts/mcp_users_web.py`),
with `--env dev|prod`. Names come from the code above: the table and session
prefix from `public_web.py`, the pool found by its exact name with
`ListUserPools` (exactly one match, or the command fails). Output never holds
a user name, email, tenant id, pool id, parameter name or fingerprint. A
failed AWS call exits with code 1 and prints only its error code.

- `web-status` (read only): the interpreted configuration row (or
  `MALFORMED` with the attribute names present), the breaker state and the
  current window's rejections, what `/estado` would answer, occupied seats,
  users in the web pool and session parameters with the age of the oldest.
  Exit code 0, or 3 when something is one hour old or older or a listing
  stopped early. This is the cheap way to see why sign-ins fail.
- `web-stats [--days 14] [--months 3]` (read only): the day and month rows,
  one consistent `GetItem` each; an absent row prints zeros, a malformed
  counter prints `?`.
- `web-config [--cap N] [--open true|false] [--pause-until <ISO-8601 UTC>|none]
  [--pass-required true|false] [--yes]`: prints the current and the new values
  and writes nothing without `--yes`. The write is one `UpdateItem` that sets
  only the requested attributes, never `occupied`, conditional on the row and
  each changed attribute still holding the value read (otherwise nothing is
  written). It refuses a change that would leave the row malformed (for
  example an unknown attribute already present). `--cap` is 0 to 1000000;
  `--pause-until` must be in the future and in UTC (`Z` or `+00:00`); `none`
  lifts a pause.

Changing the configuration is a write in the environment's table: in
production it is a production change.

## How it is tested

Offline (no network, no AWS, no MAPIT, no Cloudflare):

- unit tests per module with injected clients: `tests/test_public_web.py`,
  `test_public_identity.py`, `test_public_pass.py`, `test_public_web_service.py`,
  `test_public_sweep.py`, `test_public_web_contract.py`;
- the same flows against the real botocore models with `botocore.stub.Stubber`
  (requests validated against the service model, parsed responses):
  `test_public_*_sdk.py` and the `web-*` tests in `tests/test_mcp_users.py`;
- `tests/test_multiuser_template_pinned.py`: the invitation-only templates are
  unchanged byte for byte and never mention the public mode; the module tests
  check that with `MAPIT_WEB_MODE` absent the invitation code path runs;
- every new test is seen failing once against deliberately broken code.

Offline tests prove the contract as read from the documentation and the SDK
models; they do not prove Cognito trigger order, cold-start time against the
5-second trigger limit, Turnstile behaviour, TTL timing or real MAPIT answers.

Manual test in DEV, before any automated evaluation, with the web running
locally against the DEV web stack:

1. Sign in with a MAPIT account without invitation; compare five figures with
   the invitation-only web.
2. Sign out; `web-status` shows 0 users and 0 session parameters.
3. Sign in, close the tab without signing out; after one hour `web-status`
   shows 0 users and 0 session parameters, and the oldest age never reached
   60 minutes.
4. With `--cap 1` and one person inside: an unknown email with a wrong
   password gets "bad credentials", not "no seats". "No seats" can only be
   seen with a second real account; otherwise it is covered by tests only.
5. Five wrong passwords for an invented email lock it for 15 minutes (two
   passes needed).
6. Measure the cold start of the sign-in against the 5-second limit.
7. Open the Cognito login URL directly, without the web: refused, and the
   day's `mapit_rejections` does not move (`web-stats`).
8. Request a pass, wait more than 5 minutes, try to sign in: refused.
9. Normal path on desktop and on an iPhone: the check appears, resolves and
   the email arrives prefilled.
10. Sign in, then within the same hour try a direct Cognito login without a
    pass: refused.

## Known risks

- **Active-session detection.** With a pass and a wrong password, Cognito
  answers with its own error when the user still exists (signed in less than
  about 50 minutes ago) and with the migration's when it does not; text and
  timing tell them apart. The pass and Cognito's own lockout bound it; no text
  avoids it.
- **The breaker does not see failures against existing users.** For a user
  still in the pool, Cognito checks the password itself and no trigger learns
  the result, so those failures add neither to the attempts row nor to the
  breaker. They still spend pass attempts.
- **Burst at a window change.** The breaker, the per-IP pass count and the
  per-minute call limit use fixed windows: up to `2N - 2` breaker rejections
  (38) fit in ten minutes that span a window change, about twice the per-minute
  call limit fits in a few seconds around a minute change, and the same for
  passes per IP.
- Two racing MAPIT rejections for one email may both add instead of locking;
  the next one locks.
- Anyone who knows an email can lock it for 15 minutes or spend its pass, and
  can open the breaker for everybody, by solving the check each time.
- If Cloudflare does not answer, nobody new can sign in (fails closed);
  `--pass-required false` removes the requirement while it lasts.
- The consent is recorded because the only way into the pool is the web, which
  always shows the screen; the server does not see the checkbox.

## Not implemented

- Automatic pause from a daily call ceiling: only the manual `--open false` and
  `--pause-until` exist.
- Per-day tool call counts and monthly distinct people: the day and month rows
  hold only the counters listed above.
