# Changelog

All notable changes to `django-tokenforge` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
