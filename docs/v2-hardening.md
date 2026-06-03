# tokenforge v2 — Security Hardening Plan

> Status: **complete**. 1.1–1.5 shipped the opt-in hardening; **2.0.0** flipped the safe
> modes to default (§5). This document is the spec for the v2 effort. It is not shipped
> with the package (the `docs/` directory is excluded from the sdist/wheel).

## 0. North star

Make tokenforge **very hard to exploit** — close real edge cases and loopholes, and turn
controls that only *look* strong into controls that *are*. This is a hardening release,
not a feature release.

**Hard constraints (do not violate):**

- **Stay in-core.** tokenforge is a lean, single-issuer DRF auth package built on a
  *custom* compact token (`base64url(payload).base64url(hmac)`), stdlib crypto only
  (`hmac`/`hashlib`), Django + DRF as the only required deps. v2 does **not** become a
  JWT/JOSE/OAuth library, does **not** add asymmetric signing, and does **not** add
  multi-service `aud`/`iss` semantics. Those were explicitly ruled out.
- **Backward compatible / opt-in.** v1 tokens and v1 config keep working. New behaviour
  activates only when configured. The Cashra project (already on v1) must be able to
  upgrade with zero forced re-auth.
- **Pattern A versioning.** Ship hardening as additive **`1.x` minor releases**. Reserve
  **`2.0.0`** for the single deliberate breaking flip (make the safe modes the default,
  drop legacy paths). See §6.

---

## 1. How tokenforge is integrated today (grounding)

Reviewed in `cashra/portal-backend`. This is what a *real, deep* integration looks like,
and it determines which findings are live in production.

- **Swapped token model** — `users.UserRefreshToken(AbstractRefreshToken)` adds a
  `device_session` FK (`on_delete=SET_NULL`) for per-device revocation. Registered via
  `TOKENFORGE["TOKEN_MODEL"]`; `TOKENFORGE_TOKEN_MODEL` stays the default.
- **Wrapper** — `users.services.auth_token_service.AuthTokenService` is the *only* entry
  point; the rest of the codebase never imports tokenforge directly.
- **All callbacks wired** — `DEVICE_SESSION_VALIDATOR` (revoked + inactivity gate),
  `RISK_EVENT_HANDLER`, `DEVICE_SESSION_LOADER`, `USER_SERIALIZER`, `FINGERPRINT_FUNCTION`.
  So the M1 "fail-open if fields absent" gap does **not** bite Cashra — but it bites any
  consumer who wires the gates without the fields.
- **Uses tokenforge's `ExchangeCreateView`/`ExchangeRedeemView` directly** for
  cross-subdomain SSO → **H3, SD-2, SD-3 are live in the SSO path.**
- **Wraps the package `TokenRefreshView`** (web) → the **H2 `tnt` header injection is in
  the request path** (claim appears unused downstream in Cashra today, but it is still set
  from a client header).
- **`REFRESH_TOKEN_COOKIE_DOMAIN = ".cashra.app"` in production** → **SD-1 is live.**
- The config comment asserts *"Hard-fail is always enforced at refresh token rotation"* →
  the team **believes H1's control exists**; it does not.
- **Pattern propagation:** `AuthTokenService` re-implements tokenforge's exchange
  single-use + counter pattern as "step-up grants" — **including the same non-atomic
  `cache.get` → `cache.delete` race (H3)** and the same approximate counter. This is the
  strongest signal in the whole review: the single-use primitive must be **fixed once and
  made reusable**, or every consumer that copies the pattern re-introduces the bug.

**Live-in-prod findings:** H1 (false belief), H2 (in path), H3 + SD-2 + SD-3 (SSO),
SD-1 (cookie), plus the duplicated racy single-use in step-up grants.

---

## 2. Threat model

**In scope (what v2 must make hard):**
1. Token **forgery / tampering** (already strong — keep it that way).
2. Token **theft & replay** (stolen access/refresh/exchange token reuse).
3. **Race conditions** that break single-use / rotation invariants.
4. **Claim-trust** errors (signed claims carrying unvalidated client input).
5. **Configuration footguns** that silently widen exposure (esp. cross-subdomain).
6. **Robustness / DoS** (unhandled exceptions, unbounded growth).

**Out of scope (non-goals):** asymmetric signing, JWT interop, multi-service `aud`/`iss`,
OAuth flows. Access tokens remain short-lived bearer credentials: theft within the TTL is
*mitigated* (kill-switch) not *eliminated* — that is an accepted property of stateless auth.

---

## 3. Findings & fixes

Each entry: **severity · where · exploit · fix (how) · backward-compat · tests · release.**
IDs match the audit (`H` = high, `SD` = subdomain/config, `M` = medium, `L` = low).

### H1 — Device fingerprint binding enforces nothing (false assurance)
- **Where:** `tokens.py` docstring claims hard-fail at refresh; `services/refresh.py`
  drift check only `logger.warning(...)` + risk event, then rotates. `tokens.py` access
  check is soft unless `FINGERPRINT_STRICT_ACCESS_TOKEN=True` (default `False`).
- **Exploit:** use a stolen refresh/access token from any IP/UA — succeeds, only logs.
- **Fix:**
  1. Add `FINGERPRINT_STRICT_REFRESH` (default **`True`** in 2.0; `False` in 1.x for
     opt-in). When true, `rotate_refresh_token` **raises** on drift instead of only logging.
  2. Make the drift comparison robust to the documented mobile-IP churn: compare a
     **stable component** (e.g. UA + a coarse network signal) rather than the full
     `SHA256(IP|UA)`, OR expose `FINGERPRINT_COMPONENTS` so deployments choose. The hard
     gate should key off the part that does *not* legitimately change mid-session.
  3. Fix the `tokens.py` docstring so no one trusts a non-existent control.
  4. **Per-call / per-view override** so mobile is exempt. `rotate_refresh_token(...,
     strict_fingerprint=...)` and a `TokenRefreshView.strict_fingerprint` class
     attribute override the global setting (`None` = use the global). **Mobile must
     not enforce fingerprint hard-fail** — mobile IP/UA is unstable (WiFi↔LTE,
     carrier NAT) and the real mobile boundary is the **device session / device id**
     (validated via `DEVICE_SESSION_VALIDATOR` and, in cashra,
     `MobileRefreshGuardService`'s `X-Device-Id` check). The mobile refresh view sets
     `strict_fingerprint = False`; web can enforce. Fingerprint binding is a
     web-oriented heuristic, not a mobile control.
- **Compat:** opt-in via setting in 1.x; becomes default in 2.0 (web paths only —
  mobile views keep `strict_fingerprint = False`).
- **Tests:** rotation with matching fp succeeds; drift with strict on → `ValueError`;
  drift with strict off → succeeds + warns + risk event; per-call override beats the
  global both ways.
- **Release:** 1.2 (opt-in + override), default-on for web in 2.0.

### H2 — `tnt` claim is set from a client-controlled header
- **Where:** `views.py` (`TokenRefreshView`, `ExchangeRedeemView`):
  `tenant_slug = request.META.get("HTTP_X_TENANT_SLUG", "")` → signed into the token.
- **Exploit:** client sends `X-Tenant-Slug: <other-tenant>`; the signed `tnt` now asserts
  it. Any consumer using `request.auth["tnt"]` for authz = cross-tenant escalation.
- **Fix:** stop reading `tnt` from a header in the package views. Options (pick one):
  - **Drop it** from the default views (cleanest — Cashra doesn't use it).
  - Or add a `TENANT_RESOLVER` callback `fn(request, user) -> str | None` so the slug is
    **server-derived** (from the user / device session), never client-asserted.
  - Document loudly that **`tnt` is advisory and must never be trusted for authorization
    unless server-validated.**
- **Compat:** removing header-sourced `tnt` is technically a behaviour change; keep the
  field in 1.x but source it from the resolver (default → empty), drop the header read.
- **Tests:** `X-Tenant-Slug` header has no effect on the issued token; resolver value (if
  configured) is what lands in `tnt`.
- **Release:** 1.2.

### H3 — Exchange-token single-use is racy (get-then-delete) — and the pattern is copied
- **Where:** `services/exchange.py` `redeem_exchange_token`: `cache.get(key)` → validate →
  `cache.delete(key)`. Two concurrent redeems both read non-`None` before either deletes →
  the one-time token redeems twice. The same race exists in Cashra's `redeem_step_up_grant`.
- **Exploit:** token leaks in a URL (SD-4); fire two redeems in parallel within the TTL →
  two sessions from one single-use token.
- **Fix:** introduce a **reusable atomic single-use primitive** and route both exchange
  tokens and (by example) consumer step-up grants through it:
  - New module `tokenforge/onetime.py`: `claim(key) -> payload | None` that performs an
    **atomic get-and-delete**. Implementation order of preference:
    1. Redis `GETDEL` (Redis ≥ 6.2) via the configured cache client when available.
    2. A small Lua `GET`+`DEL` script when the backend is `django-redis`.
    3. Portable fallback: `cache.add(claim_marker, 1, nx)` *before* reading — only the
       winner of the `add` proceeds; everyone else treats it as already-consumed.
  - `create_one_time(payload, ttl) -> token` / `claim(token) -> payload` become the public
    single-use API; `create_exchange_token`/`redeem_exchange_token` build on it.
- **Compat:** internal; public exchange API unchanged. Expose `tokenforge.onetime` so
  consumers (Cashra step-up) can drop their racy copy.
- **Tests:** concurrent `claim` of the same token → exactly one success (assert via
  threads / a stubbed non-atomic backend); single-use after success.
- **Release:** 1.1 (this is foundational and fixes a live bug).

### H4 — Replay detection's family revocation is rolled back (found during v2 work)
- **Where:** `rotate_refresh_token` is wrapped in `transaction.atomic`. The replay branch
  called `_revoke_family(...)` and then `raise`d **inside** the transaction.
- **Exploit:** replaying a revoked refresh token logged "REPLAY DETECTED" and ran the
  family `UPDATE`, but the `raise` rolled the `UPDATE` back — so the **entire token family
  stayed usable**. The package's headline replay-detection feature didn't actually revoke.
  Empirically confirmed (after rotation A→B, replaying A left B active).
- **Fix:** restructure so the lock + rotation run inside the atomic block, but replay
  handling (family revocation + raise) runs **after** the block commits, making the
  revocation durable. Expiry-path self-revoke stays inside (benign if rolled back — the
  token is expired anyway).
- **Tests:** regression test — after a replay, the previously-active child token is revoked.
- **Release:** 1.5.

### SD-1 — Domain-wide refresh cookie leaks the token to every subdomain
- **Where:** `REFRESH_TOKEN_COOKIE_DOMAIN=".cashra.app"` (prod). Any `*.cashra.app` —
  including a taken-over or user-content subdomain — receives the refresh cookie (a page on
  `evil.cashra.app` can `fetch("/api/v1/auth/token/refresh/")` and capture it server-side;
  HttpOnly doesn't help).
- **Fix:**
  1. **Discourage in code:** emit a `warnings.warn(...)` (and log) at config load when
     `REFRESH_TOKEN_COOKIE_DOMAIN` is set, pointing at the exchange flow.
  2. Document the secure topology: **host-only refresh cookie per subdomain + exchange
     flow for handoff.** Domain-wide cookies are for "all subdomains fully trusted, no
     takeover risk" only.
  3. Add a `__Secure-` cookie name prefix option (`USE_SECURE_COOKIE_PREFIX`) for defence
     in depth.
- **Compat:** warning only; no behaviour change. In 2.0, consider refusing domain-wide +
  `path="/"` together (see SD-5).
- **Tests:** warning emitted when domain set; exchange-flow integration test proving
  host-only cookies + handoff works end-to-end.
- **Release:** 1.3 (warnings + docs); enforcement in 2.0.

### SD-2 — No allowlist for exchange `target_origin`
- **Where:** `ExchangeCreateView` accepts any `target_origin` (URLField only).
- **Exploit:** XSS/CSRF on the base domain mints an exchange token for an attacker origin;
  attacker redeems from their own origin (origin binding passes) → victim's session.
- **Fix:** add `EXCHANGE_ALLOWED_ORIGINS` (list of exact normalised origins). In
  `create_exchange_token`, **reject** any `target_origin` not on the list. Empty/unset =
  refuse all (fail closed) or log a loud warning that any origin is allowed (decide:
  recommend fail-closed by default in 2.0, warn in 1.x).
- **Compat:** opt-in in 1.x (unset → current behaviour + warning); fail-closed default in 2.0.
- **Tests:** create with allowed origin → ok; disallowed → 400/403; unset → warns.
- **Release:** 1.3.

### SD-3 — Exchange redemption ignores the stored device fingerprint
- **Where:** `create_exchange_token` stores `fp`; `redeem_exchange_token` /
  `ExchangeRedeemView` never compare it to the redeeming request's fingerprint.
- **Exploit:** a leaked exchange token (rides in a URL) is redeemable from any device.
- **Fix:** pass the redeeming request's fingerprint into `redeem_exchange_token` and
  compare against the stored `fp` (16-char prefix, constant-time). Gate strict/soft with
  `EXCHANGE_FINGERPRINT_STRICT` (default soft in 1.x, strict in 2.0) given the same mobile
  caveat as H1.
- **Compat:** opt-in; the view already computes a fingerprint, just isn't comparing it.
- **Tests:** matching fp → redeem ok; mismatched fp + strict → reject; + soft → ok + warn.
- **Release:** 1.3.

### SD-4 — Exchange token travels in the URL query string
- **Where:** cross-subdomain handoff passes `?token=`.
- **Exploit:** leaks via Referer, browser history, access logs; third-party resources on
  the landing page can read it from the referrer.
- **Fix (mostly docs + a helper):** recommend delivering the token in the **URL fragment**
  (`#token=`, never sent to servers/Referer) or a short-lived POST handoff; recommend
  `Referrer-Policy: no-referrer` on the redeem page. Pair with SD-3 so a leaked token is
  device-bound. Optionally ship a tiny JS snippet / doc recipe for fragment handoff.
- **Release:** 1.3 (docs); SD-3 binding does the real mitigation.

### SD-5 — Cookie path/domain footguns
- **Where:** `REFRESH_TOKEN_COOKIE_PATH` must match the mount point; widening to `"/"` to
  "make it work" exposes the cookie to every path on the host. `path="/"` + a set
  `COOKIE_DOMAIN` is the worst case.
- **Fix:** startup check (app `ready()` or settings access) that **warns** on
  `path == "/"`, and **errors/warns loudly** on `path == "/"` *and* a non-`None` domain.
- **Release:** 1.3 (warn); refuse the dangerous combo in 2.0.

### SD-6 — Cross-subdomain CORS / SameSite guidance
- Subdomains are **same-site**, so `SameSite=Lax` does **not** isolate `a.example.com`
  from `b.example.com`; only cookie **Domain scope + the exchange flow** isolate them.
  Cross-subdomain credentialed XHR needs a **strict CORS origin allowlist** (never `*`
  with credentials, never reflect `Origin`).
- **Fix:** documentation section. (Consuming app owns CORS, but the docs must state this
  because it gates whether SD-1/SD-2 are reachable.)
- **Release:** 1.3 (docs).

### M1 — Device-session risk/bot checks silently fail open
- **Where:** `rotate_refresh_token` default branch uses `getattr(session, "risk_score", 0)`
  etc. Missing fields → all gates pass silently.
- **Fix:** when the default gates are relied on (no custom validator), validate that the
  session object exposes the expected attributes; otherwise `warnings.warn` once. Better:
  require an explicit `DEVICE_SESSION_VALIDATOR` to enable gating, and make the built-in
  defaults a documented opt-in rather than silent.
- **Release:** 1.4.

### M2 — Stolen access token usable for the full TTL, no revocation (the kill-switch)
- **Where:** stateless access tokens, by design. No `jti`, no denylist, no logout view.
- **Fix:**
  1. Add an optional **`jti`** claim (uuid4) to access tokens (cheap; also aids audit).
  2. `ACCESS_TOKEN_DENYLIST_ENABLED` (default off). When on, `verify_access_token` does one
     Redis check (`tokenforge:denylist:<jti>`); logout/compromise adds the `jti` with TTL =
     remaining lifetime. Document the per-request Redis cost this re-introduces.
  3. Ship `LogoutView` (revoke current family + clear cookie + denylist current `jti` if
     enabled) and `LogoutAllView` (`revoke_all_for_user` + bulk denylist). Login stays
     app-specific.
- **Compat:** all opt-in; `jti` is additive to the payload (still signed).
- **Tests:** denylisted `jti` → 401; logout revokes family + clears cookie; logout-all.
- **Release:** 1.3 (kill-switch is a headline v2 item).

### M3 — User cache serves stale authorization for up to `USER_CACHE_TTL`
- **Where:** `authentication.py` caches the full `User`; `is_active` staleness handled,
  but role/permission/group changes lag up to 5 min.
- **Fix:** add a per-user **auth epoch** key (`tokenforge:userver:<id>`); cache stores the
  epoch alongside the user; bump the epoch on permission/role change (expose
  `bump_user_auth_epoch(user_id)`); a mismatch forces a DB re-fetch. Keep returning a real
  `User` (DRF permissions need it). Document `invalidate_user_cache` + the new epoch hook.
- **Release:** 1.4.

### M4 — `SELECT FOR UPDATE(of=...)` race protection degrades off Postgres
- **Where:** `rotate_refresh_token`. On SQLite it is a no-op; `of=` unsupported on some DBs.
- **Fix:** detect the DB vendor; if not Postgres and `REPLAY_DETECTION_ENABLED`, `warn`
  that concurrent-rotation protection is reduced. Document Postgres as the supported DB for
  the concurrency guarantee.
- **Release:** 1.4.

### Low-severity / robustness
- **L1 — Non-ASCII signature → 500.** `hmac.compare_digest` raises `TypeError` on a
  non-ASCII `provided_sig`; `authentication.py` only catches `ValueError`. **Fix:** in
  `verify_access_token`, validate the token is ASCII before compare, and have
  `BearerTokenAuthentication` map *any* exception from verification to one
  `AuthenticationFailed`. **Release:** 1.1.
- **L2 — Refresh double-submit nukes the family.** A legit retry/two-tab refresh reuses a
  just-rotated token → family revoked → full logout; an attacker who captures a refresh
  token can force-logout the victim. **Fix:** optional short **grace window** — accept the
  immediately-previous token for `REFRESH_REUSE_GRACE_SECONDS` (default 0) **iff** same
  fingerprint and the replacement exists, returning the already-rotated child instead of
  revoking. Off by default (keeps strict replay semantics). **Release:** 1.4.
- **L3 — No signing-key strength check.** **Fix:** enforce a minimum length (e.g. ≥ 32
  bytes) for `ACCESS_TOKEN_SIGNING_KEY` at first use; raise `ImproperlyConfigured` if too
  short. **Release:** 1.1.
- **L4 — Exchange token in URL** — see SD-4.
- **L5 — No cap on active refresh tokens per user.** **Fix:** optional
  `MAX_ACTIVE_REFRESH_TOKENS_PER_USER`; on create, prune/oldest-revoke beyond the cap.
  **Release:** 1.4.
- **L6 — Hygiene:** the `v` claim is required-but-never-validated (versioning is a no-op);
  the hardcoded `v="v2"` in a v1 package; `except (json.JSONDecodeError, Exception)` is
  redundant; the version is duplicated in `pyproject.toml` + `__init__.py`. **Fix:** define
  real format versions (legacy = `v1`, anything new = `v2+`) and **validate** `v` on
  verify; single-source the package version (dynamic). **Release:** 1.1.

### Cross-cutting — a reusable, hardened single-use primitive (`tokenforge.onetime`)
The exchange token and Cashra's step-up grant are the *same* short-TTL, single-use,
device/origin-bound Redis pattern — and both share the H3 race and the approximate counter.
v2 should extract this into one audited primitive:
- Atomic claim (H3 fix).
- Accurate active-count via a **per-user Redis set** of live token ids (`SCARD`) instead of
  an incr/decr int that drifts on expiry (fixes the exchange/step-up counter).
- Optional fingerprint + origin/purpose binding baked in.
Exchange tokens build on it; consumers (Cashra step-up) can adopt it and delete their copy.

---

## 4. New / changed settings (all opt-in until 2.0)

| Setting | Default (1.x) | Default (2.0) | Finding |
|---|---|---|---|
| `FINGERPRINT_STRICT_REFRESH` | `False` | `True` | H1 |
| `FINGERPRINT_COMPONENTS` | `["ip","ua"]` | `["ua"]` | H1 |
| `TENANT_RESOLVER` | `None` (no `tnt` from header) | — | H2 |
| `EXCHANGE_ALLOWED_ORIGINS` | `None` (warn) | required / fail-closed | SD-2 |
| `EXCHANGE_FINGERPRINT_STRICT` | `False` | `True` | SD-3 |
| `ACCESS_TOKEN_DENYLIST_ENABLED` | `False` | `False` | M2 |
| `USE_SECURE_COOKIE_PREFIX` | `False` | `True` | SD-1 |
| `REFRESH_REUSE_GRACE_SECONDS` | `0` | `0` | L2 |
| `MAX_ACTIVE_REFRESH_TOKENS_PER_USER` | `None` | `None` | L5 |
| min signing-key length | enforced (≥32B) | enforced | L3 |

New endpoints: `POST /token/logout/`, `POST /token/logout-all/` (M2).
New modules: `tokenforge/onetime.py` (H3 + counter), denylist helpers (M2).

---

## 5. Release sequencing (Pattern A)

- **1.1 — Correctness & foundations** ✅ *shipped on the v2 branch:*
  `tokenforge.onetime` atomic single-use (H3), L1 (no 500s), L3 (key strength), L6
  (validate `v`, single-source version, drop redundant except).
- **1.2 — Enforcement made real (opt-in)** ✅ *shipped:* H1 (`FINGERPRINT_STRICT_REFRESH`
  + per-call/per-view `strict_fingerprint` override), H2 (`tnt` via `TENANT_RESOLVER`, no
  longer header-sourced).
- **1.3 — Mobile refresh** ✅ *shipped:* `MobileTokenRefreshView` + `MobileClientMixin`
  (body token, platform guard, reject-cookie, `strict_fingerprint=False`, no-XHR via
  `require_xhr_header`, `pre_rotation_guard` hook). The generic guards live in the package;
  device-id / integrity binding stays a consumer hook (depends on the device-session
  schema — keeping it generic would be drift).
- **1.4 — Subdomain + kill-switch** ✅ *shipped:* SD-2 (`EXCHANGE_ALLOWED_ORIGINS`), SD-3
  (`EXCHANGE_FINGERPRINT_STRICT`, fp-bound redeem), SD-1/SD-5 (cookie-config startup
  warnings), M2 (`jti` + `ACCESS_TOKEN_DENYLIST_ENABLED` + `tokenforge.denylist` +
  `LogoutView`/`LogoutAllView` + `revoke_by_raw_token`). SD-4 (URL fragment / Referrer-
  Policy) and SD-6 (CORS guidance) are README docs.
- **1.5 — Remaining hardening** ✅ *shipped:* **H4** (durable replay revocation — a real
  pre-existing bug found during this work: the replay branch revoked the family then
  `raise`d *inside* `transaction.atomic`, rolling the revocation back; now handled after
  commit), M1 (device-gate fail-open warning), M4 (non-Postgres warning), L2
  (`REFRESH_REUSE_GRACE_SECONDS`), L5 (`MAX_ACTIVE_REFRESH_TOKENS_PER_USER`). **M3 was
  already solved** by `invalidate_user_cache` (1.0). Still deferred:
  `USE_SECURE_COOKIE_PREFIX` (`__Secure-`, SD-1) and the SCARD-accurate exchange counter.
- **2.0 — The deliberate flip** ✅ *shipped:* safe modes are now default —
  `FINGERPRINT_STRICT_REFRESH=True` + `FINGERPRINT_COMPONENTS=["ua"]` (H1), fail-closed
  `EXCHANGE_ALLOWED_ORIGINS` → `403` when unset (SD-2), `EXCHANGE_FINGERPRINT_STRICT=True`
  (SD-3), `USE_SECURE_COOKIE_PREFIX=True` with a `__Secure-` prefix via
  `cookies.refresh_cookie_name()` (SD-1), and the domain-wide-**and**-`path="/"` combo is
  now a startup `ImproperlyConfigured` (SD-5). **Structure/design (2.0):** the package was
  reorganised into domain sub-packages (`tokens/`, `security/`, `api/`, `models/` alongside
  `services/`; Django wiring stays flat) and the domain API is now **100% class-based** —
  `AccessToken`, `OneTimeStore`, `AccessTokenDenylist`, `RequestFingerprint`, `RefreshCookie`,
  `UserCache`, `ExchangeTokenService`, `RefreshTokenService`, `TokenSignals`, `BaseTokenView`
  — no module-level domain functions (framework seams — the settings singleton, callback
  hooks, `get_token_model` — stay idiomatic). **L3 decided:** the `<32`-byte signing-key
  check stays a hard error (it only breaks an already-weak config). **Polish landed:**
  accurate self-pruning active-token counter in `tokenforge.onetime`
  (`track`/`untrack`/`count_active`) replacing the drift-prone int counter; SD-4 (URL
  fragment + `Referrer-Policy`) and SD-6 (same-site / CORS) written into the README
  Security Notes. **No legacy code paths remained to drop** — the header-sourced `tnt`
  (H2) and redundant excepts were removed as they were found in 1.1–1.2. **249 tests,
  91.4% coverage, ruff + mypy(strict) green.** A `1.x` maintenance branch should be cut
  from the 1.5.0 commit for Cashra before it adopts 2.0.

---

## 6. Test plan (exploit-proving)

Every finding ships with a test that **demonstrates the exploit is closed**, not just that
the happy path works:
- H1: drift + strict → `ValueError`; drift + soft → success + warning + risk event.
- H2: `X-Tenant-Slug` header does not influence the issued token.
- H3: concurrent `claim()` of one token → exactly one success (thread/stub backend).
- SD-2: disallowed `target_origin` rejected; allowed accepted.
- SD-3: mismatched fingerprint rejected under strict.
- M2: denylisted `jti` → 401; logout revokes family + clears cookie.
- L1: non-ASCII Bearer token → 401 (never 500).
- L3: short signing key → `ImproperlyConfigured`.
- L6: token with a bad/old `v` rejected when format validation is active.
Keep strict mypy, ruff, and the 85% coverage gate green throughout.

---

## 7. Cashra (portal-backend) migration guidance

Once v2 lands, the changes Cashra should make:
1. **Cookie topology (SD-1):** move off the `.cashra.app` domain-wide refresh cookie to
   **host-only cookies + the exchange flow**, or formally accept the domain-wide risk and
   guarantee no untrusted/dangling `*.cashra.app` subdomains (+ takeover monitoring).
2. **Exchange (SD-2/SD-3):** set `EXCHANGE_ALLOWED_ORIGINS` to the known Cashra origins;
   enable fingerprint-bound redemption.
3. **Fingerprint (H1):** enable `FINGERPRINT_STRICT_REFRESH` and correct the misleading
   config comment; verify mobile WiFi↔LTE churn doesn't cause spurious logouts (tune
   `FINGERPRINT_COMPONENTS`).
4. **`tnt` (H2):** confirm nothing authorizes on `request.auth["tnt"]`; the header source
   goes away regardless.
5. **Step-up grants (H3):** replace the hand-rolled `cache.get`/`cache.delete` single-use
   in `AuthTokenService` with `tokenforge.onetime` (atomic claim + accurate counter).
6. **Kill-switch (M2):** adopt `jti` + denylist so logout / compromise revokes access
   tokens immediately instead of waiting out the 15-min TTL.
7. **Auth epoch (M3):** call `bump_user_auth_epoch` on role/permission/deactivation changes
   so privilege changes take effect immediately, not after `USER_CACHE_TTL`.
