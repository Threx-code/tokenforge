# Security Policy

## Supported Versions

Security fixes are backported to the latest **minor** release series only.

| Version | Supported |
|---|---|
| 1.x (latest) | ✅ Active |
| < 1.0 | ❌ End of life |

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

If you discover a vulnerability in `django-tokenforge`, please report it responsibly so we can address it before it is publicly disclosed. Public disclosure without a prior coordinated fix puts all users at risk.

### How to report

**Option 1 — GitHub Private Security Advisory (preferred)**

Use GitHub's built-in [private vulnerability reporting](https://github.com/your-org/django-tokenforge/security/advisories/new). This creates an encrypted channel between you and the maintainers.

**Option 2 — Email**

Send a report to: **security@your-org.example.com**

Encrypt your message with our PGP key if the vulnerability is critical:

```
Key ID:      (publish your PGP key fingerprint here)
Fingerprint: (publish your PGP key fingerprint here)
```

### What to include

A useful security report includes:

1. **Affected component** — which module, endpoint, or setting is involved
2. **Vulnerability type** — e.g. token forgery, replay bypass, information disclosure, privilege escalation
3. **Impact** — what an attacker could achieve, and under what conditions
4. **Steps to reproduce** — a minimal proof of concept (code, curl commands, etc.)
5. **Suggested fix** — if you have one (optional but appreciated)
6. **Your contact details** — so we can credit you in the advisory

---

## Response Timeline

We aim to respond according to the severity of the issue:

| Severity | Initial response | Fix target |
|---|---|---|
| Critical (CVSS ≥ 9.0) | Within 24 hours | Within 7 days |
| High (CVSS 7.0–8.9) | Within 48 hours | Within 14 days |
| Medium (CVSS 4.0–6.9) | Within 5 business days | Within 30 days |
| Low (CVSS < 4.0) | Within 10 business days | Next minor release |

We will acknowledge your report, keep you updated on our progress, and credit you in the published advisory (unless you prefer to remain anonymous).

---

## Disclosure Policy

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure):

1. You report privately.
2. We confirm the vulnerability and develop a fix.
3. We release a patched version and publish a GitHub Security Advisory simultaneously.
4. After the patched version has been available for a reasonable window (typically 7 days for critical issues, 30 days for others), you are free to publish your own writeup.

---

## Scope

The following are in scope:

- Token forgery or signature bypass
- Refresh token replay bypass
- Exchange token origin-binding bypass
- Race conditions in token rotation that allow an attacker to obtain a valid token
- Authentication bypass via the `BearerTokenAuthentication` class
- Information disclosure from token payloads or error responses
- Denial-of-service vectors specific to TokenForge (e.g. Redis exhaustion via exchange token flooding)

The following are **out of scope**:

- Vulnerabilities in Django, DRF, or Redis themselves — report those to the respective projects
- Rate limiting bypasses that depend entirely on Django's throttling infrastructure
- Issues that require the attacker to already have access to the Django `SECRET_KEY` or `ACCESS_TOKEN_SIGNING_KEY`
- Social engineering or phishing

---

## Security Hardening Checklist

Before deploying TokenForge in production, verify these settings:

- [ ] `ACCESS_TOKEN_SIGNING_KEY` is a dedicated key — **never reuse `SECRET_KEY`**
- [ ] `REFRESH_TOKEN_COOKIE_SECURE` is `True` (HTTPS only)
- [ ] `REFRESH_TOKEN_COOKIE_SAMESITE` is `"Lax"` or `"Strict"` — never `"None"` without also setting `Secure`
- [ ] `REQUIRE_XHR_HEADER` is `True`
- [ ] `REPLAY_DETECTION_ENABLED` is `True`
- [ ] `RISK_EVENT_HANDLER` is configured for security monitoring and alerting
- [ ] Redis is reachable and not publicly accessible
- [ ] `NUM_PROXIES` is set to the correct number of trusted proxy hops in front of the app
- [ ] `FINGERPRINT_STRICT_ACCESS_TOKEN` is `False` unless all users have stable, fixed IPs
- [ ] Periodic `cleanup_expired_tokens()` task is scheduled to prevent unbounded table growth
- [ ] `CORS_ALLOW_CREDENTIALS = True` and `CORS_ALLOW_HEADERS` includes `authorization` and `x-requested-with`
- [ ] Cookie path is scoped to the refresh endpoint (`REFRESH_TOKEN_COOKIE_PATH`)
- [ ] `ACCESS_TOKEN_SIGNING_KEY` is stored in a secrets manager — not in version control

---

## Past Security Advisories

None yet — this is the initial public release.
