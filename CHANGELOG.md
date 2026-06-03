# Changelog

All notable changes to `django-tokenforge` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [2.0.0] — 2026-06-03

**The deliberate flip.** Every hardening control added across 1.1–1.5 was opt-in
so existing deployments could upgrade with zero behaviour change. 2.0 makes the
safe modes the **default**. No token format changed and no API was removed — but
several defaults are now stricter, so review the migration notes before upgrading.

### Changed (breaking — secure-by-default)

- **Strict refresh-fingerprint by default (H1).** `FINGERPRINT_STRICT_REFRESH`
  now defaults to **`True`**: a refresh rotation whose fingerprint doesn't match
  is **rejected**, not just logged. Set it `False` to restore 1.x monitor-only
  behaviour. Mobile is unaffected — `MobileTokenRefreshView` sets
  `strict_fingerprint = False` and binds on the device session.
- **Fingerprint is UA-only by default (H1).** `FINGERPRINT_COMPONENTS` now
  defaults to **`["ua"]`** instead of `["ip", "ua"]`, so a legitimate network
  change (WiFi↔LTE, VPN, proxy rotation) is not treated as device drift — which
  matters now that strict refresh is on. Add `"ip"` if your clients have stable,
  trusted IPs.
- **Fail-closed exchange origins (SD-2).** `EXCHANGE_ALLOWED_ORIGINS` is now
  enforced fail-closed: when it is unset/empty, `create_exchange_token` is
  **refused** (the view returns `403`). You must list your known subdomains to
  use the exchange flow. (1.x warned and allowed any origin.)
- **Strict exchange-fingerprint binding (SD-3).** `EXCHANGE_FINGERPRINT_STRICT`
  now defaults to **`True`**: a leaked exchange token can't be redeemed from a
  different device.
- **`__Secure-` cookie prefix (SD-1).** New `USE_SECURE_COOKIE_PREFIX` defaults
  to **`True`**: the refresh cookie name is prefixed with `__Secure-` so the
  browser rejects it unless set over HTTPS with the Secure flag. Automatically
  inert when `REFRESH_TOKEN_COOKIE_SECURE` is `False` (local HTTP dev), where the
  prefix would be invalid. All cookie read/write sites go through the new
  `tokenforge.cookies.refresh_cookie_name()` helper.
- **Worst-case cookie combo is now a hard error (SD-5).** A refresh cookie that
  is both domain-wide (`REFRESH_TOKEN_COOKIE_DOMAIN` set) **and** `path="/"` —
  the broadest possible exposure — now raises `ImproperlyConfigured` at startup
  instead of merely warning. Either narrowing clears it. Domain-only or
  path-only still warn.

### Decided

- **Signing-key minimum length stays a hard error (L3).** A `< 32`-byte
  `ACCESS_TOKEN_SIGNING_KEY` raises `ImproperlyConfigured` at first use. This was
  the one open call from the 1.x series: it only breaks a configuration that is
  *already* cryptographically weak, and the error tells you exactly how to fix
  it, so it is kept (not downgraded to a warning).

### Added

- **Accurate, self-pruning active-token tracking (`tokenforge.onetime.track` /
  `untrack` / `count_active`).** Replaces the per-user incr/decr integer counter
  for exchange tokens, which drifted upward whenever a token expired unredeemed
  (eventually locking the user out of the exchange flow). Each owner now has a
  pruned-on-read `{token: expiry}` set, so an expired token stops counting on its
  own. Portable across every cache backend (no Redis-only commands); a best-effort
  availability cap, not a security boundary (single-use is still enforced
  atomically by `claim()`). Reusable by consumers (e.g. Cashra step-up grants).

### Changed (breaking — structure & API are now class-based)

- **Package reorganised into domain sub-packages.** Flat modules are grouped:
  `tokenforge/tokens/` (access, onetime, denylist), `tokenforge/security/`
  (authentication, fingerprinting, cookies), `tokenforge/api/` (serializers +
  `views/`), `tokenforge/models/`, alongside the existing `services/`. Django
  wiring (`apps.py`, `urls.py`, `admin.py`, `settings.py`) stays flat.
- **100% class-based domain API — module-level functions are gone.** Migration:

  | 1.x function | 2.0 |
  |---|---|
  | `tokens.create_access_token()` / `verify_access_token()` | `tokens.AccessToken.create()` / `.verify()` |
  | `onetime.create()/claim()/track()/...` | `tokens.OneTimeStore(ns).create()/.claim()/.track()/...` |
  | `denylist.denylist_access_token()` / `is_denylisted()` | `tokens.AccessTokenDenylist.add()` / `.contains()` |
  | `services.refresh.create_refresh_token()` / `rotate_refresh_token()` / `revoke_*` / `cleanup_expired_tokens()` | `services.refresh.RefreshTokenService.create()` / `.rotate()` / `.revoke_*()` / `.cleanup_expired()` |
  | `services.exchange.create_exchange_token()` / `redeem_exchange_token()` / `count_active_exchange_tokens()` | `services.exchange.ExchangeTokenService.create()` / `.redeem()` / `.count_active()` |
  | `fingerprinting.fingerprint_for_request(req)` / `get_client_ip(req)` | `security.RequestFingerprint(req).compute()` / `.client_ip()` |
  | `cookies.set_refresh_cookie(resp, t)` / `expire_refresh_cookie(resp)` / `refresh_cookie_name()` | `security.RefreshCookie(resp).set(t)` / `.expire()` / `RefreshCookie.name()` |
  | `authentication.invalidate_user_cache()` | `security.authentication.UserCache.invalidate()` |
  | `signals.token_rotated/token_revoked/replay_detected` | `signals.TokenSignals.rotated/.revoked/.replay_detected` |

- **Import paths moved with the modules.** Notably the DRF auth class is now
  `tokenforge.security.authentication.BearerTokenAuthentication` (was
  `tokenforge.authentication.…`); update `DEFAULT_AUTHENTICATION_CLASSES`. The
  `BearerTokenAuthentication` class itself is unchanged.
- **`FINGERPRINT_FUNCTION` default is now `None`** (was a dotted path). Unset →
  the built-in `RequestFingerprint` is used; it remains a pluggable callable hook.
- **`tokenforge.urls` is unchanged** (`include("tokenforge.urls")` still works);
  the view classes moved to `tokenforge.api.views` but `tokenforge.models.RefreshToken`
  and `TOKENFORGE["TOKEN_MODEL"]` are unchanged.

### Migration

See `docs/v2-hardening.md` §7. In short: set `EXCHANGE_ALLOWED_ORIGINS`; confirm
nothing authorizes on `request.auth["tnt"]`; verify web fingerprint strictness
against your traffic (it's UA-only, so network changes are fine, but a browser
UA change mid-session will force a re-login); mobile needs no change. To upgrade
with **no** behaviour change, pin the old defaults explicitly:
`FINGERPRINT_STRICT_REFRESH=False`, `FINGERPRINT_COMPONENTS=["ip","ua"]`,
`EXCHANGE_FINGERPRINT_STRICT=False`, `USE_SECURE_COOKIE_PREFIX=False`, and set
`EXCHANGE_ALLOWED_ORIGINS` to your origins.

---

## [1.5.0] — 2026-06-03

Final hardening pass — and a fix for a real pre-existing replay-detection bug.

### Fixed

- **Replay detection now actually revokes the family (H4).** `rotate_refresh_token`
  is wrapped in `transaction.atomic`; the replay branch revoked the token family
  and then `raise`d **inside** that transaction, so the revocation was **rolled
  back**. Replaying a revoked token logged a warning but left the entire family
  usable — defeating the headline replay-detection feature. Rotation now performs
  replay handling **after** the transaction commits, so the family revocation is
  durable. (Verified by a regression test.)

### Security / Added

- **Refresh-reuse grace window (`REFRESH_REUSE_GRACE_SECONDS`, L2).** A legitimate
  double-submit / retry — reusing a just-rotated token whose replacement is still
  active, with a matching fingerprint — is treated as a rotation of the current
  token instead of a replay that revokes the whole family. `0` = strict (default),
  so behaviour is unchanged unless you opt in.
- **Active-token cap (`MAX_ACTIVE_REFRESH_TOKENS_PER_USER`, L5).** On a new login
  beyond the cap, the oldest active tokens are revoked. Rotations don't count
  toward the cap. `None` = unlimited (default).
- **Device-gate fail-open warning (M1).** When the built-in refresh gates run
  (no `DEVICE_SESSION_VALIDATOR`) against a session exposing none of
  `revoked`/`risk_score`/`bot_score`, a warning is emitted — those gates were
  otherwise silently no-ops.
- **Non-PostgreSQL concurrency warning (M4).** A startup warning when the database
  vendor isn't PostgreSQL and replay detection is enabled, because the
  `SELECT FOR UPDATE (of=…)` that serialises concurrent rotation only fully holds
  on PostgreSQL.

### Settings

- Added `REFRESH_REUSE_GRACE_SECONDS`, `MAX_ACTIVE_REFRESH_TOKENS_PER_USER`.

### Notes

- M3 (instant invalidation on permission change) is already provided by
  `invalidate_user_cache(user_id)` (since 1.0) — see the Cache Invalidation
  section of the README; no new machinery was added.

---

## [1.4.0] — 2026-06-03

Cross-subdomain hardening and an access-token kill-switch. All new behaviour is
opt-in / backward compatible.

### Security

- **Exchange origin allowlist (`EXCHANGE_ALLOWED_ORIGINS`).** When set,
  `create_exchange_token` rejects any `target_origin` not on the list, so an
  exchange token can never be minted for an attacker origin. Unset = any origin
  accepted (a one-time warning is emitted).
- **Fingerprint-bound exchange redemption (`EXCHANGE_FINGERPRINT_STRICT`).**
  `redeem_exchange_token` compares the redeeming request's fingerprint to the one
  bound at creation; with strict on, a mismatch is rejected — a leaked exchange
  token (it rides in a URL) can't be redeemed from another device. Off by default
  (mismatch is logged).
- **Access-token kill-switch (`ACCESS_TOKEN_DENYLIST_ENABLED`).** Access tokens
  now carry a `jti`. When the denylist is enabled, the auth path checks a Redis
  denylist (one GET per request) and logout / compromise denylists the `jti` for
  its remaining lifetime — so a stateless access token can be revoked immediately
  instead of waiting out its lifetime. Off by default (keeps the zero-DB-query
  auth path); the denylist entry self-expires with the token.
- **Unsafe cookie-config warnings (SD-1 / SD-5).** A startup warning fires when
  `REFRESH_TOKEN_COOKIE_DOMAIN` is set (a domain-wide cookie reaches every
  subdomain, including a hostile/taken-over one, which can capture the token) and
  when `REFRESH_TOKEN_COOKIE_PATH` is `"/"`, with a louder warning for both at once.

### Added

- **`POST logout/`** (`LogoutView`) — revoke this session's refresh-token family,
  denylist the presented access token (if enabled), clear the cookie. Refresh
  token from the cookie (web) or body (mobile). Always `204`.
- **`POST logout-all/`** (`LogoutAllView`) — revoke every refresh token for the
  authenticated user + denylist the current access token.
- **`tokenforge.denylist`** — `denylist_access_token(jti, *, exp=|ttl=)` and
  `is_denylisted(jti)`.
- **`revoke_by_raw_token(raw_token)`** in `tokenforge.services.refresh`.
- Access-token `jti` claim (optional on verify → backward compatible).

### Settings

- Added `EXCHANGE_ALLOWED_ORIGINS`, `EXCHANGE_FINGERPRINT_STRICT`,
  `ACCESS_TOKEN_DENYLIST_ENABLED`.

### Notes

- SD-4 (deliver the exchange token in the URL **fragment** / set `Referrer-Policy:
  no-referrer`) and SD-6 (cross-subdomain CORS guidance) are documentation items.

---

## [1.3.0] — 2026-06-03

Adds a first-class, hardened mobile refresh endpoint. Backward compatible.

### Added

- **`MobileTokenRefreshView` + `MobileClientMixin`** — a body-based refresh
  endpoint for native mobile clients, so apps don't have to hand-roll one:
  - reads the refresh token from the **request body** (not a cookie) and returns
    the rotated token in the **body** for secure device storage;
  - **platform guard** — requires `X-Client-Platform: mobile` and **rejects any
    request that carries the refresh cookie**, keeping the web cookie/CSRF
    surface off the mobile endpoint (so only a real mobile client can use it);
  - `strict_fingerprint = False` baked in — mobile IP/UA is unstable; bind on the
    device session instead;
  - does not require `X-Requested-With` (no ambient cookie → no CSRF surface);
  - the full rotation pipeline (replay detection, device-session validation,
    rotation) still runs, identical to the web flow;
  - a `pre_rotation_guard(request, raw_token)` **hook** for app-specific device
    binding (device-id match, integrity attestation, …) — kept as a hook because
    it depends on your device-session schema, not the package's.
  - Route: `POST mobile/token/refresh/`.
- **`TokenRefreshView.require_xhr_header`** — per-view override of the global
  `REQUIRE_XHR_HEADER` (`None` = use the global). `MobileTokenRefreshView` sets
  it `False`.

---

## [1.2.0] — 2026-06-03

Enforcement layer of the v2 hardening track. Backward compatible — new
behaviour is opt-in via settings.

### Security

- **Hard-fail on refresh-token fingerprint drift (opt-in).** New
  `FINGERPRINT_STRICT_REFRESH` (default `False`). When enabled,
  `rotate_refresh_token` **rejects** a rotation whose fingerprint differs from
  the one bound at issuance, instead of only logging. This makes device binding
  an actual security boundary rather than monitoring. (Previously the docstrings
  claimed this was already enforced — it was not; the comments are corrected.)
  - **Per-call / per-view override.** `rotate_refresh_token(...,
    strict_fingerprint=...)` and a `TokenRefreshView.strict_fingerprint` class
    attribute override the global setting (`None` = use the global). This lets a
    deployment enforce on **web** while exempting **mobile** — whose IP/UA is not
    stable and which binds on the device session / device id instead. A mobile
    refresh view sets `strict_fingerprint = False` so a network change never logs
    the user out; drift is still logged + risk-evented.
- **Configurable fingerprint components.** New `FINGERPRINT_COMPONENTS`
  (default `["ip", "ua"]`, unchanged behaviour). Set to `["ua"]` for a
  network-stable fingerprint so strict refresh enforcement doesn't log out
  mobile users on a WiFi↔LTE change.
- **`tnt` claim is no longer sourced from a client header.** The tenant slug was
  read from the client-controlled `X-Tenant-Slug` header and signed into the
  access token, giving a forged-but-signed claim. It is now resolved
  **server-side** via the optional `TENANT_RESOLVER` callback
  (`fn(request, user) -> str | None`); with no resolver configured, `tnt` is
  empty. A signed claim never carries unvalidated client input.

### Settings

- Added `FINGERPRINT_STRICT_REFRESH`, `FINGERPRINT_COMPONENTS`, `TENANT_RESOLVER`.

---

## [1.1.0] — 2026-06-03

First release of the v2 security-hardening track (see `docs/v2-hardening.md`).
All changes are backward compatible — existing tokens and configuration keep
working.

### Security

- **Atomic single-use tokens (`tokenforge.onetime`).** New primitive with an
  **atomic `claim()`** that fixes a single-use race: the previous
  `cache.get()` → `cache.delete()` pattern let two concurrent redemptions both
  consume the same token. `claim()` arbitrates on the cache's `delete()` return
  value, so exactly one concurrent caller wins on every supported backend.
  **Exchange-token redemption now builds on this** (cache-key shape unchanged).
  The primitive is public so apps that roll their own single-use grants (e.g.
  step-up / re-auth) can drop their racy copies.
- **Minimum signing-key length.** `ACCESS_TOKEN_SIGNING_KEY` shorter than 32
  bytes now raises `ImproperlyConfigured` instead of silently weakening every
  token.
- **Malformed tokens never 500.** A non-ASCII signature segment previously made
  `hmac.compare_digest` raise `TypeError`, which escaped as a 500;
  verification now normalises all malformed input to an authentication failure
  (`BearerTokenAuthentication` maps any verification error to one 401).
- **Token format version is validated.** The `v` claim is now checked against a
  known set; unknown formats are rejected (forward-compatible safety). The value
  is a named constant (`ACCESS_TOKEN_FORMAT_VERSION`) instead of a magic string.

### Changed

- Version is now single-sourced from `tokenforge.__init__.__version__`
  (`pyproject.toml` uses dynamic version) so it can no longer drift.
- Removed the deprecated `default_app_config` (ignored since Django 4.1; the
  app config is auto-detected on all supported Django versions).

---

## [1.0.0] — 2026-02-19

Initial public release.

### Added

#### Core Token Lifecycle
- **HMAC-SHA256 access tokens** — stateless, zero-DB-query authentication on every request.
  - Format: `base64url(payload).base64url(signature)`
  - Payload claims: `sub` (user ID), `sid` (device session), `fp` (fingerprint), `tnt` (tenant slug), `iat`, `exp`, `v` (version), `token_type`
  - 15-minute lifetime by default (`ACCESS_TOKEN_LIFETIME_SECONDS`)
- **Database-backed refresh tokens** with automatic rotation on every use.
  - 384 bits of entropy (`secrets.token_urlsafe(48)`)
  - Only the SHA-256 hash of the raw token is stored — the raw value is never persisted
  - HttpOnly, path-scoped cookie delivery — browser sends the cookie only to the refresh endpoint
  - 30-day lifetime by default (`REFRESH_TOKEN_LIFETIME_DAYS`)
- **Token family replay detection** — reusing any revoked refresh token in a family immediately revokes all tokens in the same family and fires the `replay_detected` signal.
- **`SELECT FOR UPDATE`** on refresh token rotation to prevent concurrent rotation race conditions.
- **Exchange tokens** — Redis-backed, single-use, origin-bound, 60-second TTL tokens for cross-subdomain SSO handoff (`/exchange/create/` → `/exchange/redeem/`).

#### Security
- **Device fingerprinting** — `SHA-256(IP | User-Agent)` binding at token issuance with configurable strict/soft enforcement (`FINGERPRINT_STRICT_ACCESS_TOKEN`).
- **`NUM_PROXIES`-aware IP extraction** — reads `X-Forwarded-For` from the correct position in the proxy chain, preventing client IP spoofing.
- **Anti-CSRF** — `X-Requested-With: XMLHttpRequest` required on `POST /token/refresh/` (`REQUIRE_XHR_HEADER`).
- **Oversized cookie guard** — rejects `refresh_token` cookie values over 512 bytes before any processing.
- **Risk/bot score thresholds** — configurable rejection gates (`RISK_SCORE_THRESHOLD`, `BOT_SCORE_THRESHOLD`) checked during refresh rotation if the device session model carries these fields.

#### Extensibility
- **Swappable token model** — extend `AbstractRefreshToken` to add custom fields (e.g. a FK to a device session model), exactly like Django's `AUTH_USER_MODEL` pattern. Declare `TOKENFORGE_TOKEN_MODEL` and `TOKENFORGE["TOKEN_MODEL"]` in settings; use `get_token_model()` in code.
- **Configurable callbacks** via dotted import paths:
  - `RISK_EVENT_HANDLER` — called on replay detection and fingerprint drift
  - `DEVICE_SESSION_VALIDATOR` — called during rotation to gate on session state
  - `DEVICE_SESSION_LOADER` — called during exchange redemption to hydrate the device session
  - `USER_SERIALIZER` — DRF serializer class included in the exchange redeem response
  - `FINGERPRINT_FUNCTION` — override the entire fingerprint computation
- **Django signals**: `token_rotated`, `token_revoked`, `replay_detected`

#### Developer Experience
- **Knox-style settings** — single `TOKENFORGE = {}` dict; no scattered `TOKENFORGE_*` keys (except the required `TOKENFORGE_TOKEN_MODEL` for Django's swappable registry).
- **User cache** — User objects cached in Redis for `USER_CACHE_TTL` seconds (default 5 min) to eliminate per-request DB queries. `invalidate_user_cache(user_id)` for immediate eviction.
- **Django Admin integration** — refresh tokens visible in admin; raw token value never exposed.
- **`cleanup_expired_tokens()`** — utility for periodic removal of expired/revoked tokens older than N days.
- **Full TypeScript frontend integration guide** — in-memory access token store, silent refresh with race-condition deduplication, Axios interceptors, page-load recovery, background refresh timer, cross-subdomain navigation.

#### Endpoints
- `POST /token/refresh/` — rotate refresh token, issue new access token
- `POST /exchange/create/` — create a one-time exchange token (authenticated)
- `POST /exchange/redeem/` — redeem exchange token, issue full token pair (unauthenticated)

#### Public API
- `tokenforge.tokens`: `create_access_token`, `verify_access_token`
- `tokenforge.services.refresh`: `create_refresh_token`, `rotate_refresh_token`, `revoke_by_family`, `revoke_all_for_user`, `revoke_by_device_session`, `get_active_token_for_session`, `cleanup_expired_tokens`
- `tokenforge.services.exchange`: `create_exchange_token`, `redeem_exchange_token`, `count_active_exchange_tokens`, `increment_exchange_counter`, `decrement_exchange_counter`
- `tokenforge.authentication`: `BearerTokenAuthentication`, `invalidate_user_cache`
- `tokenforge.cookies`: `set_refresh_cookie`, `expire_refresh_cookie`
- `tokenforge.fingerprinting`: `fingerprint_for_request`, `get_client_ip`
- `tokenforge.models`: `AbstractRefreshToken`, `RefreshToken`, `get_token_model`
- `tokenforge.signals`: `token_rotated`, `token_revoked`, `replay_detected`

### Fixed
- `RefreshToken.Meta` now declares `app_label = "tokenforge"` explicitly, preventing `RuntimeError` when the model module is imported before the app registry is fully populated.
- `TOKENFORGE_TOKEN_MODEL` is derived with `.get()` fallback (`TOKENFORGE.get("TOKEN_MODEL", "tokenforge.RefreshToken")`), preventing `AttributeError` on projects that omit `TOKEN_MODEL` from the `TOKENFORGE` dict.

### Requirements
- Python 3.10+
- Django 4.2, 5.0, 5.1, 5.2
- Django REST Framework 3.14+
- Redis (required for exchange tokens and user caching)
- PostgreSQL recommended (for `SELECT FOR UPDATE` concurrent rotation safety)

---

[Unreleased]: https://github.com/your-org/django-tokenforge/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/your-org/django-tokenforge/releases/tag/v1.0.0
