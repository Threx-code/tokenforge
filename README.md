# django-tokenforge

**Stateless Bearer token authentication for Django REST Framework.**

TokenForge provides a complete, production-ready token lifecycle for SPAs and mobile apps: HMAC-SHA256 signed access tokens with zero database queries per request, refresh tokens with automatic rotation and replay detection, and one-time exchange tokens for cross-subdomain authentication handoff via Redis.

Designed as a security-first drop-in replacement for `django-rest-knox` when you need stateless access tokens and proper refresh token rotation.

---

## Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration Reference](#configuration-reference)
- [Swappable Token Model](#swappable-token-model)
- [Endpoints](#endpoints)
- [Callbacks](#callbacks)
- [Django Signals](#django-signals)
- [Cache Invalidation](#cache-invalidation)
- [Frontend Integration](#frontend-integration)
- [Periodic Cleanup](#periodic-cleanup)
- [Security Notes](#security-notes)
- [API Reference](#api-reference)

---

## Features

| Feature | Details |
|---|---|
| **Stateless access tokens** | HMAC-SHA256 signed, zero DB queries per authenticated request |
| **Refresh token rotation** | Token family tracking — every rotation issues a new token and revokes the old one |
| **Replay detection** | Reusing a revoked refresh token immediately revokes the entire token family |
| **Exchange tokens** | One-time Redis-backed tokens for cross-subdomain SSO handoff |
| **Swappable token model** | Extend `AbstractRefreshToken` exactly like Django's `AUTH_USER_MODEL` |
| **Configurable callbacks** | Risk event handler, device session validator, device session loader, user serializer |
| **Device fingerprinting** | SHA-256(IP + User-Agent) binding with configurable soft/strict enforcement |
| **Safe X-Forwarded-For** | `NUM_PROXIES`-aware IP extraction — not blindly trusting the leftmost XFF value |
| **Anti-CSRF** | `X-Requested-With: XMLHttpRequest` required on the refresh endpoint |
| **Django signals** | `TokenSignals.rotated`, `TokenSignals.revoked`, `TokenSignals.replay_detected` |
| **Knox-style settings** | Single `TOKENFORGE = {}` dict — no scattered settings |
| **Admin integration** | Refresh tokens visible in Django admin; token hash never exposed |

---

## How It Works

### Token Architecture

TokenForge issues two tokens on login:

```
┌─────────────────────────────────────────────────────────────────┐
│                         LOGIN RESPONSE                          │
│                                                                 │
│  Body:   { "access_token": "...", "expires_in": 900 }          │
│  Cookie: Set-Cookie: refresh_token=...; HttpOnly; Secure;       │
│                       Path=/api/v1/auth/token/refresh/          │
└─────────────────────────────────────────────────────────────────┘
```

**Access Token** — stateless, lives in JS memory only
- Format: `base64url(json_payload).base64url(hmac_sha256_signature)`
- Verified with a pure HMAC computation — no database touch
- 15-minute lifetime by default
- Sent by the client as `Authorization: Bearer <token>` on every request

**Refresh Token** — database-backed, lives in an HttpOnly cookie
- 384 bits of entropy (`secrets.token_urlsafe(48)`)
- Only the SHA-256 hash is stored in the database; the raw value is sent once
- Path-scoped to `/api/v1/auth/token/refresh/` — the browser only sends it to that single endpoint
- 30-day lifetime with sliding rotation

### Refresh Token Rotation & Replay Detection

```
Login          →  RefreshToken A  (family = F1)
First refresh  →  RefreshToken A revoked
                  RefreshToken B created  (family = F1)
Second refresh →  RefreshToken B revoked
                  RefreshToken C created  (family = F1)

Attacker replays A  →  Entire family F1 revoked (A, B, C)
                        TokenSignals.replay_detected signal fired
                        RISK_EVENT_HANDLER called (if configured)
```

Concurrent rotation is protected by `SELECT FOR UPDATE` on the token row — two simultaneous refresh requests cannot both succeed on the same token.

### Exchange Tokens (Cross-Subdomain SSO)

```
app.example.com                          admin.example.com
      │                                         │
      │  POST /exchange/create/                 │
      │  { "target_origin": "https://admin..." }│
      │◄─ { "exchange_token": "...", "ttl": 60 }│
      │                                         │
      │  redirect ?token=<exchange_token> ─────►│
      │                                         │  POST /exchange/redeem/
      │                                         │  { "exchange_token": "..." }
      │                                         │◄─ { "access_token": "..." }
      │                                         │   Set-Cookie: refresh_token=...
```

Exchange tokens are single-use, origin-bound, Redis-backed, and expire in 60 seconds.

---

## Requirements

- Python 3.10+
- Django 4.2+
- Django REST Framework 3.14+
- Redis (for exchange tokens — via Django's cache framework)
- PostgreSQL recommended (`select_for_update(of=("self",))` is used for safe concurrent rotation)

---

## Installation

**1. Add to your project**

Copy the `tokenforge/` directory into your Django project's source root, or install via PyPI when available:

```bash
pip install django-tokenforge
```

**2. Add to `INSTALLED_APPS`**

```python
# settings.py
INSTALLED_APPS = [
    ...
    "tokenforge",
    ...
]
```

**3. Run migrations**

```bash
python manage.py migrate tokenforge
```

**4. Generate a dedicated signing key**

```bash
openssl rand -base64 64
```

Add the output to your environment — **never reuse `SECRET_KEY`**:

```bash
# .env
TOKENFORGE_SIGNING_KEY=your_generated_value_here
```

---

## Quick Start

### Minimal Settings

```python
# settings.py

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "tokenforge.security.authentication.BearerTokenAuthentication",
    ],
}

TOKENFORGE = {
    "ACCESS_TOKEN_SIGNING_KEY": env("TOKENFORGE_SIGNING_KEY"),  # Required
    "REFRESH_TOKEN_COOKIE_SECURE": True,   # False only for local dev
}
```

### Wire Up URLs

```python
# urls.py
from django.urls import path, include

urlpatterns = [
    path("api/v1/auth/", include("tokenforge.urls")),
]
```

This registers three endpoints — see [Endpoints](#endpoints) for full details.

### Issue Tokens After Login

TokenForge does not include a login view — authentication is your application's responsibility. After verifying credentials and any MFA, issue tokens like this:

```python
from tokenforge.tokens import AccessToken
from tokenforge.services.refresh import RefreshTokenService
from tokenforge.security.cookies import RefreshCookie
from tokenforge.security.fingerprinting import RequestFingerprint

def my_login_view(request, user):
    fingerprint = RequestFingerprint(request).compute()

    raw_refresh, refresh_instance = RefreshTokenService.create(
        user=user,
        fingerprint=fingerprint,
        # device_session=device_session_instance,  # optional
    )

    access_token, expires_in = AccessToken.create(
        user_id=str(user.id),
        fingerprint=fingerprint,
        # device_session_id=str(device_session.id),  # optional
        # tenant_slug="my-tenant",                   # optional
    )

    response = Response({
        "access_token": access_token,
        "expires_in": expires_in,
    })
    RefreshCookie(response).set(raw_refresh)
    return response
```

### Protect Views

```python
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

class MyProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # request.user  — the authenticated User instance
        # request.auth  — dict: {sub, sid, fp, tnt, iat, exp, v, token_type}
        user_id    = request.auth["sub"]   # UUID string
        session_id = request.auth["sid"]   # device session UUID string
        tenant     = request.auth["tnt"]   # tenant slug (or empty string)
        return Response({"user": str(request.user)})
```

### Revoke Tokens (Logout)

```python
from tokenforge.services.refresh import RefreshTokenService
from tokenforge.security.cookies import RefreshCookie

# Single-device logout — revoke only the current session's tokens
def logout_view(request):
    session_id = request.auth.get("sid")
    if session_id:
        device_session = MyDeviceSession.objects.get(id=session_id)
        RefreshTokenService.revoke_by_device_session(device_session)
    response = Response({"detail": "Logged out."})
    RefreshCookie(response).expire()
    return response

# All-device logout — revoke every refresh token for this user
def logout_all_view(request):
    RefreshTokenService.revoke_all_for_user(request.user)
    response = Response({"detail": "Logged out from all devices."})
    RefreshCookie(response).expire()
    return response
```

---

## Configuration Reference

All settings live in a single `TOKENFORGE` dictionary.

```python
TOKENFORGE = {
    # ── Access Token ─────────────────────────────────────────────────────────
    "ACCESS_TOKEN_LIFETIME_SECONDS": 900,
    # Required. Generate with: openssl rand -base64 64
    # Must be distinct from SECRET_KEY — a compromised SECRET_KEY must not
    # also compromise access token signatures.
    "ACCESS_TOKEN_SIGNING_KEY": None,

    # ── Refresh Token ─────────────────────────────────────────────────────────
    "REFRESH_TOKEN_LIFETIME_DAYS": 30,
    "REFRESH_TOKEN_BYTES": 48,                    # 384 bits of entropy
    "REFRESH_TOKEN_COOKIE_NAME": "refresh_token",
    "REFRESH_TOKEN_COOKIE_PATH": "/api/v1/auth/token/refresh/",
    "REFRESH_TOKEN_COOKIE_SECURE": True,          # Secure by default; set False only for local dev
    "REFRESH_TOKEN_COOKIE_SAMESITE": "Lax",
    "REFRESH_TOKEN_COOKIE_DOMAIN": None,          # None = host-only; ".example.com" for cross-subdomain
    "USE_SECURE_COOKIE_PREFIX": True,             # `__Secure-` prefix (auto-skipped when COOKIE_SECURE=False)
    "TOKEN_MODEL": "tokenforge.RefreshToken",

    # ── Exchange Token ────────────────────────────────────────────────────────
    "EXCHANGE_TOKEN_TTL_SECONDS": 60,
    "EXCHANGE_TOKEN_BYTES": 48,                   # 384 bits of entropy
    "EXCHANGE_TOKEN_MAX_ACTIVE": 5,               # Max concurrent tokens per user
    # FAIL-CLOSED: unset/empty refuses all exchange creation (403). List your subdomains.
    "EXCHANGE_ALLOWED_ORIGINS": None,
    "EXCHANGE_FINGERPRINT_STRICT": True,          # Reject redemption from a different device

    # ── Security ──────────────────────────────────────────────────────────────
    "FINGERPRINT_ENABLED": True,
    "FINGERPRINT_COMPONENTS": ["ua"],             # UA-only (network-stable); add "ip" for fixed-IP fleets
    # Refresh rotation hard-fails on fingerprint drift (2.0 default). The mobile
    # view opts out automatically; set False here for 1.x monitor-only behaviour.
    "FINGERPRINT_STRICT_REFRESH": True,
    # Access-token drift is soft-warn by default. True = hard-fail; only for
    # stable-IP fleets (internal tools behind a fixed VPN), never mobile/SPA.
    "FINGERPRINT_STRICT_ACCESS_TOKEN": False,
    "REPLAY_DETECTION_ENABLED": True,
    "RISK_SCORE_THRESHOLD": 60,   # Block refresh if device session risk_score >= threshold
    "BOT_SCORE_THRESHOLD": 90,    # Block refresh if device session bot_score >= threshold
    "USER_CACHE_TTL": 300,        # Seconds to cache user objects per access token verify

    # ── Callbacks ─────────────────────────────────────────────────────────────
    # All values must be dotted paths to module-level functions (not class methods).
    "RISK_EVENT_HANDLER": None,        # fn(event_type, severity, user, request, **kw)
    "DEVICE_SESSION_VALIDATOR": None,  # fn(device_session) -> None or raise ValueError
    "DEVICE_SESSION_LOADER": None,     # fn(session_id, user) -> session or None
    "USER_SERIALIZER": None,           # DRF Serializer class for exchange redeem response
    "FINGERPRINT_FUNCTION": None,   # None = built-in RequestFingerprint; or any callable fn(request)->str

    # ── Anti-CSRF ─────────────────────────────────────────────────────────────
    "REQUIRE_XHR_HEADER": True,  # Require X-Requested-With: XMLHttpRequest on /token/refresh/
}
```

### Settings Table

| Setting | Type | Default | Description |
|---|---|---|---|
| `ACCESS_TOKEN_LIFETIME_SECONDS` | `int` | `900` | Access token validity window in seconds |
| `ACCESS_TOKEN_SIGNING_KEY` | `str` | `None` | **Required.** Dedicated HMAC-SHA256 signing key (≥ 32 bytes). Never share with `SECRET_KEY` |
| `ACCESS_TOKEN_DENYLIST_ENABLED` | `bool` | `False` | Kill-switch: every token carries a `jti`; the auth path checks a Redis denylist so logout/compromise revokes a token immediately (one cache GET/request) |
| `REFRESH_TOKEN_LIFETIME_DAYS` | `int` | `30` | Refresh token validity in days |
| `REFRESH_TOKEN_BYTES` | `int` | `48` | Entropy bytes for refresh token generation (384 bits) |
| `REFRESH_TOKEN_COOKIE_NAME` | `str` | `"refresh_token"` | Cookie name for the refresh token |
| `REFRESH_TOKEN_COOKIE_PATH` | `str` | `"/api/v1/auth/token/refresh/"` | Cookie path scope — browser only sends cookie to this path |
| `REFRESH_TOKEN_COOKIE_SECURE` | `bool` | `True` | HTTPS-only cookie. Set `False` only in local dev |
| `REFRESH_TOKEN_COOKIE_SAMESITE` | `str` | `"Lax"` | Cookie `SameSite` attribute |
| `REFRESH_TOKEN_COOKIE_DOMAIN` | `str\|None` | `None` | `None` = host-only. Set `".example.com"` for cross-subdomain refresh (warned — see Security Notes). Domain set **and** `path="/"` is a hard error |
| `USE_SECURE_COOKIE_PREFIX` | `bool` | `True` | Prefix the refresh cookie name with `__Secure-` so the browser rejects it unless Secure/HTTPS. Auto-skipped when `REFRESH_TOKEN_COOKIE_SECURE=False` (local dev) |
| `REFRESH_REUSE_GRACE_SECONDS` | `int` | `0` | Grace window for a legit refresh double-submit/retry. `>0` rotates the current token instead of treating the reuse as a replay |
| `MAX_ACTIVE_REFRESH_TOKENS_PER_USER` | `int\|None` | `None` | Cap on concurrent active refresh tokens (≈ sessions) per user. Oldest are revoked on a new login beyond the cap |
| `TOKEN_MODEL` | `str` | `"tokenforge.RefreshToken"` | Dotted path to the active refresh token model |
| `EXCHANGE_TOKEN_TTL_SECONDS` | `int` | `60` | Exchange token lifetime in seconds |
| `EXCHANGE_TOKEN_BYTES` | `int` | `48` | Entropy bytes for exchange token generation |
| `EXCHANGE_TOKEN_MAX_ACTIVE` | `int` | `5` | Maximum concurrent active exchange tokens per user |
| `EXCHANGE_ALLOWED_ORIGINS` | `list[str]\|None` | `None` | Allowlist of permitted exchange `target_origin` values. **Fail-closed:** `None`/empty **refuses** all creation (view returns `403`). Set to your known subdomains to use the exchange flow |
| `EXCHANGE_FINGERPRINT_STRICT` | `bool` | `True` | Hard-fail exchange redemption when the redeeming request's fingerprint doesn't match the one bound at creation |
| `FINGERPRINT_ENABLED` | `bool` | `True` | Enable device fingerprint computation and binding |
| `FINGERPRINT_COMPONENTS` | `list[str]` | `["ua"]` | Which request parts form the fingerprint. Default `["ua"]` is network-stable (survives mobile WiFi↔LTE / VPN). Add `"ip"` only for stable, trusted client IPs |
| `FINGERPRINT_STRICT_ACCESS_TOKEN` | `bool` | `False` | Hard-fail on access token fingerprint drift. Off by default — see [Security Notes](#security-notes) |
| `FINGERPRINT_STRICT_REFRESH` | `bool` | `True` | Hard-fail refresh **rotation** on fingerprint drift (on by default in 2.0). Paired with `FINGERPRINT_COMPONENTS=["ua"]`; **automatically off for the mobile path** (see `MobileTokenRefreshView`). Set `False` for 1.x monitor-only behaviour |
| `REPLAY_DETECTION_ENABLED` | `bool` | `True` | Revoke entire token family when a revoked token is reused |
| `RISK_SCORE_THRESHOLD` | `int` | `60` | Reject refresh rotation if `device_session.risk_score >= this` |
| `BOT_SCORE_THRESHOLD` | `int` | `90` | Reject refresh rotation if `device_session.bot_score >= this` |
| `USER_CACHE_TTL` | `int` | `300` | Seconds to cache User objects in Redis after first DB load |
| `RISK_EVENT_HANDLER` | `str\|None` | `None` | Dotted path to risk event callback function |
| `DEVICE_SESSION_VALIDATOR` | `str\|None` | `None` | Dotted path to device session validation function |
| `DEVICE_SESSION_LOADER` | `str\|None` | `None` | Dotted path to device session loader function |
| `USER_SERIALIZER` | `str\|None` | `None` | Dotted path to DRF Serializer for exchange redeem user payload |
| `FINGERPRINT_FUNCTION` | `str\|None` | `None` | Optional override — any callable `fn(request) -> str`. `None` uses the built-in `RequestFingerprint` |
| `TENANT_RESOLVER` | `str\|None` | `None` | Dotted path to `fn(request, user) -> str\|None` resolving the access token `tnt` claim **server-side**. Never sourced from a client header |
| `REQUIRE_XHR_HEADER` | `bool` | `True` | Anti-CSRF: require `X-Requested-With: XMLHttpRequest` on `/token/refresh/` (overridable per-view via `TokenRefreshView.require_xhr_header`) |

---

## Swappable Token Model

Like Django's `AUTH_USER_MODEL`, the refresh token model is swappable. This lets you add custom fields — most commonly a foreign key to your own device session model.

### Default Model Fields

The built-in `tokenforge.RefreshToken` provides:

| Field | Type | Description |
|---|---|---|
| `id` | `UUIDField` | Primary key |
| `user` | `ForeignKey` | The owning user |
| `token_hash` | `CharField` | SHA-256 hex digest of the raw token (unique, indexed) |
| `token_family` | `UUIDField` | Groups all rotated descendants for replay detection (indexed) |
| `fingerprint` | `CharField` | SHA-256(IP\|UA) computed at issuance time |
| `expires_at` | `DateTimeField` | Expiry timestamp |
| `revoked` | `BooleanField` | Revocation flag |
| `revoked_at` | `DateTimeField` | Revocation timestamp (nullable) |
| `replaced_by` | `ForeignKey(self)` | Points to the token that replaced this one on rotation |
| `created_at` | `DateTimeField` | Auto-set on creation |

### Custom Model

```python
# myapp/models.py
from tokenforge.models import AbstractRefreshToken
from django.db import models

class MyRefreshToken(AbstractRefreshToken):
    device_session = models.ForeignKey(
        "myapp.DeviceSession",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="refresh_tokens",
    )

    class Meta(AbstractRefreshToken.Meta):
        db_table = "my_refresh_tokens"
```

```python
# settings.py
TOKENFORGE = {
    "TOKEN_MODEL": "myapp.MyRefreshToken",
}
# Required: Django's swappable registry needs this as a top-level setting.
# Must match TOKENFORGE["TOKEN_MODEL"] exactly.
TOKENFORGE_TOKEN_MODEL = "myapp.MyRefreshToken"
```

> **Set `TOKEN_MODEL` before your first migration.** Changing the model after data exists requires a manual data migration.

> **`TOKENFORGE_TOKEN_MODEL` is mandatory when using a custom model.** Django resolves swappable model identities via top-level settings (like `AUTH_USER_MODEL`). The `TOKENFORGE` dict alone is not sufficient — you must also declare `TOKENFORGE_TOKEN_MODEL` at the top level of your settings file, set to the same dotted path.

### Custom Model `app_label` Requirement

Always declare an explicit `app_label` in your custom model's `Meta` class:

```python
class MyRefreshToken(AbstractRefreshToken):
    device_session = models.ForeignKey(...)

    class Meta(AbstractRefreshToken.Meta):
        app_label = "myapp"          # Required — prevents RuntimeError on app startup
        db_table = "my_refresh_tokens"
```

Without `app_label`, Django may raise `RuntimeError: Model class myapp.models.MyRefreshToken doesn't declare an explicit app_label` when the model module is imported before the app registry is fully populated.

### Resolving the Active Model

```python
from tokenforge.models import get_token_model

TokenModel = get_token_model()
active_tokens = TokenModel.objects.filter(user=user, revoked=False)
```

---

## Endpoints

Include TokenForge's URL patterns in your project:

```python
path("api/v1/auth/", include("tokenforge.urls")),
```

### `POST /api/v1/auth/token/refresh/`

Exchange the `refresh_token` cookie for a new access token. The refresh token is rotated on every successful call.

**Required headers:**

```
X-Requested-With: XMLHttpRequest
```

**Request:** No body. The `refresh_token` HttpOnly cookie is sent automatically by the browser.

**Response `200 OK`:**

```json
{
    "access_token": "<new_access_token>",
    "expires_in": 900
}
```

A rotated `refresh_token` cookie is set in the response.

**Response `401 Unauthorized`** — token absent, expired, or revoked:

```json
{ "detail": "Session expired" }
```

**Response `403 Forbidden`** — missing `X-Requested-With` header:

```json
{ "detail": "Authentication failed" }
```

---

### `POST /api/v1/auth/mobile/token/refresh/`

Body-based refresh for **native mobile clients** (`MobileTokenRefreshView`).
Unlike the web endpoint, the token travels in the request body and the rotated
token is returned in the body — mobile apps persist it in secure device storage,
not a cookie. The full rotation pipeline (replay detection, session validation,
rotation) still runs.

**Required headers:**

```
X-Client-Platform: mobile
```

`X-Requested-With` is **not** required (no ambient cookie → no CSRF surface).

**Request:**

```json
{ "refresh_token": "<value from secure storage>" }
```

**Response `200 OK`:** (no `Set-Cookie` is issued)

```json
{
    "access_token": "<new_access_token>",
    "expires_in": 900,
    "refresh_token": "<rotated token — overwrite secure storage>"
}
```

**Response `400 Bad Request`** — not a mobile client, or the refresh cookie was
present (a real mobile client never sends it).

**Fingerprint:** the mobile path sets `strict_fingerprint = False` — mobile
IP/UA is unstable (WiFi↔LTE, carrier NAT), so device binding belongs on the
device session, not the fingerprint. Override `pre_rotation_guard(request,
raw_token)` in a subclass to enforce app-specific device binding (e.g. matching
a device-id header against the session) — that logic depends on your
device-session schema, so it stays in your project:

```python
# myapp/views.py
from rest_framework.response import Response
from rest_framework import status
from tokenforge.api.views import MobileTokenRefreshView


class AppMobileRefreshView(MobileTokenRefreshView):
    def pre_rotation_guard(self, request, raw_token):
        # Return a Response to reject (revoke first if you wish), or None to proceed.
        if not device_id_matches_session(request, raw_token):
            return Response({"detail": "Device mismatch"}, status=status.HTTP_401_UNAUTHORIZED)
        return None
```

---

### `POST /api/v1/auth/logout/`

Single-session logout. Revokes this session's refresh-token family and — when
`ACCESS_TOKEN_DENYLIST_ENABLED` is on — denylists the presented access token's
`jti` for its remaining lifetime. Clears the refresh cookie. Idempotent.

**Request:** the refresh token from the `refresh_token` cookie (web) or the body
(`{"refresh_token": "..."}`, mobile). Include `Authorization: Bearer <access>` so
the access token can be denylisted.

**Response `204 No Content`.**

---

### `POST /api/v1/auth/logout-all/`

All-session logout for the authenticated user. Revokes **every** refresh token
(no new access tokens can be minted) and denylists the current access token.
Other sessions' access tokens expire within their lifetime.

**Required:** `Authorization: Bearer <access_token>`.

**Response `204 No Content`** — or `401`/`403` if unauthenticated.

---

### `POST /api/v1/auth/exchange/create/`

Create a one-time exchange token for cross-subdomain navigation. Requires a valid Bearer token. `target_origin` must be on `EXCHANGE_ALLOWED_ORIGINS` (fail-closed — when the allowlist is unset/empty, **every** request is refused).

**Request body:**

```json
{
    "target_origin": "https://admin.example.com"
}
```

**Response `403 Forbidden`** — `target_origin` is not on `EXCHANGE_ALLOWED_ORIGINS` (or the allowlist is unset):

```json
{ "detail": "Exchange target origin is not allowed" }
```

**Response `200 OK`:**

```json
{
    "exchange_token": "<opaque_token>",
    "ttl": 60
}
```

**Response `429 Too Many Requests`** — more than `EXCHANGE_TOKEN_MAX_ACTIVE` tokens pending:

```json
{ "detail": "Too many pending exchange tokens" }
```

---

### `POST /api/v1/auth/exchange/redeem/`

Redeem a one-time exchange token. Issues a new access token and sets a new `refresh_token` cookie. No Bearer token required.

**Required headers:**

```
Origin: https://admin.example.com
```

The browser sets the `Origin` header automatically on cross-origin requests. Do not set it manually.

**Request body:**

```json
{
    "exchange_token": "<token_from_create>"
}
```

**Response `200 OK`:**

```json
{
    "access_token": "<new_access_token>",
    "expires_in": 900,
    "user": { ... }
}
```

The `"user"` key is only present when `USER_SERIALIZER` is configured.

**Response `401 Unauthorized`** — invalid token, already used, expired, or origin mismatch:

```json
{ "detail": "Authentication failed" }
```

---

## Callbacks

All callback settings take a dotted import path to a **module-level function**. DRF's `import_from_string` resolves dotted paths as `module.attribute` and cannot import class methods. Wrap them in module-level functions:

```python
# Wrong — class method
"RISK_EVENT_HANDLER": "myapp.services.RiskService.record_event"

# Correct — module-level function
"RISK_EVENT_HANDLER": "myapp.services.record_risk_event"
```

### `RISK_EVENT_HANDLER`

Called on security events: replay detection and fingerprint drift on refresh rotation.

```python
# myapp/services.py

def record_risk_event(
    *,
    event_type: str,   # "token_replay_detected" | "fingerprint_drift"
    severity: int,     # 30 = warning, 90 = critical
    user,
    request=None,
    **kwargs,          # device_session, fingerprint, metadata, risk_score, bot_score
):
    RiskEvent.objects.create(
        type=event_type,
        severity=severity,
        user=user,
        ip=RequestFingerprint(request).client_ip() if request else "",
    )
```

```python
TOKENFORGE = {
    "RISK_EVENT_HANDLER": "myapp.services.record_risk_event",
}
```

### `DEVICE_SESSION_VALIDATOR`

Called during refresh token rotation to validate that the associated device session is still permitted. Raise any exception to block the rotation.

```python
def validate_device_session(device_session) -> None:
    if device_session.revoked:
        raise ValueError("Session revoked")
    if device_session.risk_score >= 80:
        raise ValueError("Session risk score too high")
```

If not configured, TokenForge applies a built-in default check that validates `revoked`, `risk_score`, and `bot_score` fields if they exist on the session model.

### `DEVICE_SESSION_LOADER`

Called during exchange token redemption to hydrate the device session from the `sid` claim.

```python
def load_device_session(session_id: str, user) -> object | None:
    try:
        return DeviceSession.objects.get(id=session_id, user=user, revoked=False)
    except DeviceSession.DoesNotExist:
        return None
```

### `USER_SERIALIZER`

A DRF Serializer class whose output is included in the exchange redeem response under the `"user"` key.

```python
TOKENFORGE = {
    "USER_SERIALIZER": "myapp.serializers.UserSerializer",
}
```

### `FINGERPRINT_FUNCTION`

Override the default IP + User-Agent fingerprinting entirely:

```python
def my_fingerprint(request) -> str:
    import hashlib
    parts = [
        RequestFingerprint(request).client_ip(),
        request.META.get("HTTP_USER_AGENT", ""),
        request.META.get("HTTP_ACCEPT_LANGUAGE", ""),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()
```

```python
TOKENFORGE = {
    "FINGERPRINT_FUNCTION": "myapp.auth.my_fingerprint",
}
```

---

## Django Signals

```python
from tokenforge.signals import TokenSignals
from django.dispatch import receiver

@receiver(TokenSignals.rotated)
def on_rotation(sender, user, request, **kwargs):
    """Fired after a refresh token is successfully rotated."""
    logger.info("Token rotated for user %s", user.id)


@receiver(TokenSignals.revoked)
def on_revocation(sender, family, count, reason, **kwargs):
    """
    Fired after tokens are revoked.
    reason: "manual" | "replay_detection"
    count:  number of tokens revoked in this operation
    """
    logger.warning("Revoked %d tokens in family %s (reason: %s)", count, family, reason)


@receiver(TokenSignals.replay_detected)
def on_replay(sender, user, family, request, **kwargs):
    """
    Fired when a revoked refresh token is reused.
    This is a strong indicator of token theft or session compromise.
    """
    notify_security_team(user, f"Replay attack detected — family {family} fully revoked")
```

---

## Cache Invalidation

TokenForge caches User objects for `USER_CACHE_TTL` seconds (default 5 minutes) to eliminate per-request DB queries. When you deactivate a user, change their role, or modify permissions, call `UserCache.invalidate` so the next request gets a fresh DB lookup immediately:

```python
from tokenforge.security.authentication import UserCache

# After deactivating a user
user.is_active = False
user.save()
UserCache.invalidate(str(user.id))

# After changing roles or permissions
user.role = "viewer"
user.save()
UserCache.invalidate(str(user.id))
```

Set `USER_CACHE_TTL` to `0` to disable caching entirely if your application requires instant permission propagation on every request.

---

## Frontend Integration

### Token Storage

| Token | Where to store | Why |
|---|---|---|
| Access token | JavaScript memory only | `localStorage` is readable by any JS on the page (XSS). 15-min window limits exposure |
| Refresh token | HttpOnly cookie (automatic) | Set by the server — JS cannot read or modify it |
| Exchange token | URL query param (transient) | Single-use, 60s TTL — remove from URL immediately after redemption |

### In-Memory Token Store

```typescript
// auth-store.ts — module-level singleton
let accessToken: string | null = null;
let expiresAt: number = 0;

export const setTokens = (token: string, expiresIn: number) => {
    accessToken = token;
    expiresAt = Math.floor(Date.now() / 1000) + expiresIn;
};

export const getAccessToken = (): string | null => accessToken;

export const isExpired = (): boolean =>
    Math.floor(Date.now() / 1000) >= expiresAt - 30; // 30s buffer

export const clearTokens = () => {
    accessToken = null;
    expiresAt = 0;
};
```

### Silent Refresh with Race Condition Protection

Three simultaneous requests with an expired token must not each send a separate refresh call. The second call would replay an already-rotated token, triggering replay detection and killing the entire session.

```typescript
// auth.ts
let refreshPromise: Promise<string> | null = null;

export async function silentRefresh(): Promise<string> {
    // Deduplicate: queue behind any in-flight refresh
    if (refreshPromise) return refreshPromise;

    refreshPromise = fetch("/api/v1/auth/token/refresh/", {
        method: "POST",
        credentials: "include",  // Sends the HttpOnly refresh_token cookie
        headers: {
            "X-Requested-With": "XMLHttpRequest",  // Required — 403 without this
        },
    })
    .then(async (res) => {
        if (!res.ok) {
            clearTokens();
            window.location.href = "/login";
            throw new Error("Session expired");
        }
        const { access_token, expires_in } = await res.json();
        setTokens(access_token, expires_in);
        scheduleRefresh(expires_in);
        return access_token;
    })
    .finally(() => {
        refreshPromise = null;
    });

    return refreshPromise;
}
```

### Axios Interceptors

```typescript
// api.ts
import axios from "axios";
import { getAccessToken, isExpired, silentRefresh, clearTokens } from "./auth";

const api = axios.create({
    baseURL: "https://api.example.com/api/v1/",
    withCredentials: true,  // Required for the refresh cookie to be sent cross-origin
});

// Before every request: attach the access token, refreshing proactively if expired
api.interceptors.request.use(async (config) => {
    if (isExpired()) {
        await silentRefresh();
    }
    const token = getAccessToken();
    if (token) {
        config.headers["Authorization"] = `Bearer ${token}`;
    }
    return config;
});

// After every response: backstop handler for unexpected 401s
api.interceptors.response.use(
    (response) => response,
    async (error) => {
        const original = error.config;
        if (error.response?.status === 401 && !original._retried) {
            original._retried = true;
            await silentRefresh();
            return api(original);
        }
        return Promise.reject(error);
    }
);

export default api;
```

### Page Load Recovery

On hard refresh, JS memory is wiped. Attempt a silent refresh before rendering protected routes — users with a valid cookie should never see the login page.

```typescript
async function bootstrap() {
    showSplashScreen();
    try {
        await silentRefresh();
        await hydrateUserProfile();  // e.g. GET /api/v1/auth/whoami/
        renderApp();
    } catch {
        renderLoginPage();
    }
}

bootstrap();
```

### Background Refresh Timer

Refresh proactively 60 seconds before expiry so users never experience an auth delay mid-session:

```typescript
let refreshTimer: ReturnType<typeof setTimeout> | null = null;

export function scheduleRefresh(expiresIn: number) {
    if (refreshTimer) clearTimeout(refreshTimer);
    const delay = Math.max((expiresIn - 60) * 1000, 0);
    refreshTimer = setTimeout(silentRefresh, delay);
}
```

Call `scheduleRefresh(expires_in)` whenever you receive a new access token (after login, and inside `silentRefresh`).

### Cross-Subdomain Navigation

```typescript
// Source subdomain — create and hand off the exchange token
async function navigateToAdminPortal() {
    const res = await api.post("/api/v1/auth/exchange/create/", {
        target_origin: "https://admin.example.com",
    });
    const { exchange_token } = res.data;

    // Redirect immediately — token is valid for 60 seconds, single-use
    window.location.href =
        `https://admin.example.com/auth/callback?token=${exchange_token}`;
}

// Target subdomain — /auth/callback page
async function handleCallback() {
    const token = new URLSearchParams(window.location.search).get("token");
    if (!token) { window.location.href = "/login"; return; }

    // Remove the token from the URL before any async work
    window.history.replaceState({}, "", window.location.pathname);

    const res = await fetch("/api/v1/auth/exchange/redeem/", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        // Origin header is set by the browser automatically
        body: JSON.stringify({ exchange_token: token }),
    });

    if (!res.ok) { window.location.href = "/login"; return; }

    const { access_token, expires_in } = await res.json();
    setTokens(access_token, expires_in);
    scheduleRefresh(expires_in);
    window.location.href = "/dashboard";
}
```

---

## Periodic Cleanup

Revoked and expired refresh tokens remain in the database for audit purposes. Run a scheduled task to prune old records:

```python
# tasks.py (Celery)
from celery import shared_task
from tokenforge.services.refresh import RefreshTokenService
import logging

logger = logging.getLogger(__name__)

@shared_task
def cleanup_tokenforge_tokens():
    """Delete revoked tokens older than 90 days."""
    count = RefreshTokenService.cleanup_expired(older_than_days=90)
    logger.info("TokenForge cleanup: removed %d expired tokens", count)
    return count
```

```python
# Celery Beat schedule
CELERY_BEAT_SCHEDULE = {
    "cleanup-tokenforge-tokens": {
        "task": "myapp.tasks.cleanup_tokenforge_tokens",
        "schedule": crontab(hour=3, minute=0),  # Daily at 3 AM
    },
}
```

---

## Security Notes

### Production Checklist

- [ ] `ACCESS_TOKEN_SIGNING_KEY` is set to a **dedicated** key — not `SECRET_KEY` — and is **≥ 32 bytes** (shorter keys raise `ImproperlyConfigured`)
- [ ] `REFRESH_TOKEN_COOKIE_SECURE` is `True` (HTTPS only)
- [ ] `USE_SECURE_COOKIE_PREFIX` is `True` (default) so the cookie carries the `__Secure-` prefix in production
- [ ] `REFRESH_TOKEN_COOKIE_SAMESITE` is `"Lax"` or `"Strict"` — never `"None"` without `Secure`
- [ ] `REFRESH_TOKEN_COOKIE_DOMAIN` is `None` (host-only) unless you have fully audited every `*.yourdomain` subdomain — and never combined with `path="/"` (hard error)
- [ ] `EXCHANGE_ALLOWED_ORIGINS` lists your known subdomains if you use the exchange flow (creation is **fail-closed** otherwise)
- [ ] `REQUIRE_XHR_HEADER` is `True`
- [ ] `REPLAY_DETECTION_ENABLED` is `True`
- [ ] `FINGERPRINT_STRICT_REFRESH` is `True` (default) for the web flow; verify it against your traffic (it is UA-only by default, so network changes are fine)
- [ ] `RISK_EVENT_HANDLER` is configured for security monitoring
- [ ] Redis is available and reachable (required for exchange tokens and user cache)
- [ ] Periodic `RefreshTokenService.cleanup_expired()` task is scheduled
- [ ] `NUM_PROXIES` is set to the correct number of trusted proxy hops
- [ ] `FINGERPRINT_STRICT_ACCESS_TOKEN` is `False` unless all your users have stable, fixed IPs
- [ ] `x-requested-with` and `authorization` are in `CORS_ALLOW_HEADERS`
- [ ] `CORS_ALLOW_CREDENTIALS = True` with an explicit origin allowlist (never `*` with credentials)

### Key Separation

`ACCESS_TOKEN_SIGNING_KEY` must be a separate secret from `SECRET_KEY`. Django uses `SECRET_KEY` to sign sessions, CSRF tokens, and password reset links. Sharing the key means a single compromise collapses all of these simultaneously. A dedicated signing key limits the blast radius to access tokens only.

Generate one with:

```bash
openssl rand -base64 64
```

### X-Forwarded-For Trust

TokenForge's built-in fingerprint function trusts `X-Forwarded-For` only when `NUM_PROXIES > 0` is set in Django settings, reading the correct position from the **right** of the header chain rather than the leftmost value that any client can forge:

```python
# settings.py
NUM_PROXIES = 1  # One nginx / ALB / CloudFront hop in front of the app
```

With `NUM_PROXIES = 0` (default), `X-Forwarded-For` is ignored and `REMOTE_ADDR` is used directly.

### Fingerprint Drift on Mobile

The 2.0 default fingerprint is `SHA-256(User-Agent)` — **UA-only** (`FINGERPRINT_COMPONENTS = ["ua"]`). This is deliberate: `FINGERPRINT_STRICT_REFRESH` is now **on by default**, so a refresh whose fingerprint drifts is *rejected*, and binding the IP would log out every web user on a legitimate network change (WiFi↔LTE, VPN, corporate proxy rotation). UA is stable across those.

- **Web:** strict refresh-fingerprint enforcement is on. A mid-session browser User-Agent change (e.g. a browser auto-update) will force a single re-login — an accepted, rare trade-off. Set `FINGERPRINT_STRICT_REFRESH = False` to revert to monitor-only.
- **Mobile:** `MobileTokenRefreshView` sets `strict_fingerprint = False` automatically — mobile IP/UA is unstable, and the real device boundary is the device session (`DEVICE_SESSION_VALIDATOR`) plus your `pre_rotation_guard` device-id check, not a network fingerprint.
- Add `"ip"` to `FINGERPRINT_COMPONENTS` only for internal tools where all users have stable, predictable IPs.
- Access-token fingerprint mismatches remain monitor-only (logged) unless `FINGERPRINT_STRICT_ACCESS_TOKEN = True`.

### Cross-Subdomain Exchange: Token Delivery & CORS (SD-4, SD-6)

The exchange flow hands a one-time token from the base domain to a subdomain. Two properties of the delivery channel matter:

**Don't leak the token via the URL (SD-4).** A token in the query string (`?token=…`) leaks through the `Referer` header, browser history, and server access logs, and any third-party resource on the landing page can read it from the referrer. Prefer:

- Deliver the token in the **URL fragment** (`#token=…`) — fragments are never sent to the server or included in `Referer` — and have the landing page read it from `location.hash`, then immediately `history.replaceState` it away. Or use a short-lived POST handoff.
- Set `Referrer-Policy: no-referrer` (or at least `strict-origin`) on the redeem page.
- This is defence in depth: even a leaked token is **device-bound** (SD-3, `EXCHANGE_FINGERPRINT_STRICT` on by default) and single-use with a 60-second TTL, so a leak is hard to weaponise — but don't rely on that alone.

**Subdomains are same-site (SD-6).** `a.example.com` and `b.example.com` are the *same site*, so `SameSite=Lax/Strict` does **not** isolate them from each other — only the cookie's **Domain scope** (keep it host-only, see SD-1) and the exchange flow isolate subdomains. Credentialed cross-subdomain XHR additionally requires a **strict CORS origin allowlist**:

- Never use `Access-Control-Allow-Origin: *` together with credentials, and never reflect the `Origin` header unchecked.
- List exact origins in `CORS_ALLOWED_ORIGINS` and set `CORS_ALLOW_CREDENTIALS = True`.
- This is also what makes `EXCHANGE_ALLOWED_ORIGINS` reachable as a control — keep the two allowlists consistent.

CORS itself is owned by your app (`django-cors-headers`), but it gates whether the cookie/exchange protections above are actually effective.

### Scope of This Package

TokenForge handles token lifecycle only. The following are intentionally out of scope:

| Concern | Handled by |
|---|---|
| Login / registration | Your application's auth views |
| Password hashing | Django's built-in auth system |
| Rate limiting | DRF `DEFAULT_THROTTLE_RATES` |
| CORS | `django-cors-headers` |
| Email / SMS OTP | Your application's notification layer |

---

## API Reference

### `tokenforge.tokens`

```python
AccessToken.create(
    *,
    user_id: str,
    device_session_id: str = "",
    fingerprint: str = "",
    tenant_slug: str | None = None,
) -> tuple[str, int]
# Returns: (token_string, expires_in_seconds)
# Raises:  ImproperlyConfigured if ACCESS_TOKEN_SIGNING_KEY is not set

AccessToken.verify(
    token_string: str,
    *,
    request_fingerprint: str | None = None,
) -> dict
# Returns: payload dict {sub, sid, fp, tnt, iat, exp, v}
# Raises:  ValueError on signature failure, expiry, or strict fingerprint mismatch
```

### `tokenforge.services.refresh`

```python
RefreshTokenService.create(
    *,
    user,
    device_session=None,
    fingerprint: str = "",
    token_family: uuid.UUID | None = None,
) -> tuple[str, RefreshToken]
# Returns: (raw_token, RefreshToken instance)

RefreshTokenService.rotate(
    *,
    raw_token: str,
    fingerprint: str = "",
    request=None,
) -> tuple[str, RefreshToken]
# Returns: (new_raw_token, new_RefreshToken instance)
# Raises:  ValueError on validation failure (expired, revoked, replay, device rejected)

RefreshTokenService.revoke_by_family(token_family: uuid.UUID, *, reason: str = "manual") -> int
# Returns: count of tokens revoked

RefreshTokenService.revoke_all_for_user(user) -> int
# Returns: count of tokens revoked

RefreshTokenService.revoke_by_device_session(device_session) -> int
# Returns: count of tokens revoked

RefreshTokenService.get_active_token_for_session(device_session) -> RefreshToken | None

RefreshTokenService.cleanup_expired(*, older_than_days: int = 90) -> int
# Returns: count of tokens deleted
```

### `tokenforge.services.exchange`

```python
ExchangeTokenService.create(
    *,
    user_id: str,
    device_session_id: str,
    fingerprint: str = "",
    target_origin: str,
) -> str
# Returns: raw exchange token string

ExchangeTokenService.redeem(
    *,
    token: str,
    request_origin: str = "",
    request_fingerprint: str = "",   # compared to the bound fp; enforced when EXCHANGE_FINGERPRINT_STRICT
) -> dict
# Returns: {sub, sid, fp, target_origin}
# Raises:  ValueError on any validation failure

ExchangeTokenService.count_active(user_id: str) -> int
# Outstanding (non-expired) exchange tokens. Backed by tokenforge.onetime's
# pruned-on-read active set — tracking happens inside create/redeem, so there
# are no separate increment/decrement calls.
```

### `tokenforge.tokens` — `OneTimeStore` / `AccessTokenDenylist`

```python
# Atomic single-use token store, scoped to a namespace (build cross-subdomain /
# step-up grants on this). namespace is constructor state.
store = OneTimeStore(namespace="onetime")
store.create(payload: dict, *, ttl: int, nbytes=48) -> str
store.claim(token: str) -> dict | None        # atomic get-and-delete; one winner under races

# Accurate, self-pruning active-token cap (soft availability limit, per owner).
store.track(owner: str, token: str, *, ttl: int) -> None
store.untrack(owner: str, token: str) -> None
store.count_active(owner: str) -> int

# Access-token kill-switch denylist (M2).
AccessTokenDenylist.add(jti: str, *, exp: int | None = None, ttl: int | None = None) -> None
AccessTokenDenylist.contains(jti: str) -> bool
```

### `tokenforge.security.authentication`

```python
class BearerTokenAuthentication(BaseAuthentication):
    # DRF authentication class.
    # Sets request.user and request.auth on success.
    # request.auth keys: sub, sid, fp, tnt, iat, exp, v, jti, token_type

UserCache.invalidate(user_id: str) -> None
# Evict a user from the auth cache immediately.
# Call after deactivating a user or changing their permissions.
```

### `tokenforge.security.cookies`

```python
RefreshCookie(response).set(raw_token: str) -> None
# Set the refresh_token HttpOnly cookie using TOKENFORGE settings.

RefreshCookie(response).expire() -> None
# Expire the refresh_token cookie (Max-Age=0).
```

### `tokenforge.security.fingerprinting`

```python
RequestFingerprint(request).compute() -> str
# Returns: SHA-256 hex digest of "ip|user_agent"

RequestFingerprint(request).client_ip() -> str
# Returns: real client IP using NUM_PROXIES-aware X-Forwarded-For extraction
```

### `tokenforge.models`

```python
class AbstractRefreshToken(Model):
    # Abstract base — inherit to add custom fields
    is_expired: bool   # property
    is_usable:  bool   # property — not revoked and not expired

class RefreshToken(AbstractRefreshToken):
    # Default concrete model — swappable via TOKEN_MODEL

get_token_model() -> type[Model]
# Resolve the active refresh token model class (respects TOKEN_MODEL setting)
```

### `tokenforge.signals`

```python
TokenSignals.rotated    # kwargs: sender, user, request
TokenSignals.revoked    # kwargs: sender, family, count, reason
TokenSignals.replay_detected  # kwargs: sender, user, family, request
```

---

## License

MIT
