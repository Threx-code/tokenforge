# Contributing to django-tokenforge

Thank you for your interest in contributing! This document covers everything you need to get started.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Code Style](#code-style)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Bugs](#reporting-bugs)
- [Requesting Features](#requesting-features)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Release Process](#release-process)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to uphold it. Report unacceptable behaviour to the maintainers via the issue tracker.

---

## How to Contribute

Contributions are welcome in all of these forms:

- Bug reports with a minimal reproducible example
- Bug fixes (with a regression test)
- Documentation improvements
- New features (open an issue to discuss first — see [Requesting Features](#requesting-features))
- Test coverage improvements
- Security reports (see [Security Vulnerabilities](#security-vulnerabilities))

---

## Development Setup

### Prerequisites

- Python 3.10 or higher
- Redis running locally (for exchange token and cache tests)
- PostgreSQL running locally (recommended for `SELECT FOR UPDATE` tests; SQLite will skip those)

### 1. Fork and clone

```bash
git clone https://github.com/your-org/django-tokenforge.git
cd django-tokenforge
```

### 2. Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate          # macOS / Linux
# .venv\Scripts\activate           # Windows
```

### 3. Install in editable mode with dev dependencies

```bash
pip install -e ".[dev,redis]"
```

### 4. Verify the setup

```bash
pytest --tb=short
```

All tests should pass on a clean checkout.

---

## Running Tests

### Full test suite

```bash
pytest
```

### With coverage report

```bash
pytest --cov=tokenforge --cov-report=term-missing
```

### Run a specific test file or test

```bash
pytest tests/test_tokens.py
pytest tests/test_refresh.py::TestRotateRefreshToken::test_replay_detection
```

### Skip slow / integration tests

```bash
pytest -m "not slow and not integration"
```

### Test settings

Tests use `tests/settings.py`. It configures:
- `DATABASES` — SQLite by default; set `DATABASE_URL` env var to use PostgreSQL
- `CACHES` — `fakeredis` by default (no real Redis needed for unit tests); set `REDIS_URL` to use a real Redis instance
- `TOKENFORGE` — minimal test configuration with a throwaway signing key

---

## Code Style

We use [Ruff](https://github.com/astral-sh/ruff) for linting and formatting.

### Check

```bash
ruff check .
ruff format --check .
```

### Auto-fix

```bash
ruff check --fix .
ruff format .
```

### Type checking

```bash
mypy tokenforge/
```

All three must pass before a PR will be merged. The CI pipeline enforces this automatically.

---

## Submitting a Pull Request

### Branch naming

| Change type | Branch prefix | Example |
|---|---|---|
| Bug fix | `fix/` | `fix/replay-detection-race` |
| New feature | `feat/` | `feat/token-introspection-endpoint` |
| Documentation | `docs/` | `docs/cross-subdomain-guide` |
| Refactor | `refactor/` | `refactor/exchange-service-cleanup` |
| Tests | `test/` | `test/fingerprint-coverage` |
| Release | `release/` | `release/1.1.0` |

### PR checklist

Before opening a pull request, make sure you have:

- [ ] Opened an issue (for non-trivial changes) and linked it in the PR description
- [ ] Written or updated tests for any changed behaviour — coverage must not drop below 85%
- [ ] All tests pass: `pytest`
- [ ] Linting passes: `ruff check .`
- [ ] Formatting passes: `ruff format --check .`
- [ ] Type check passes: `mypy tokenforge/`
- [ ] Updated `CHANGELOG.md` under `[Unreleased]` with a concise description of the change
- [ ] Updated `README.md` if any public API, setting, or endpoint changed
- [ ] PR title is clear and descriptive (imperative mood: "Add ...", "Fix ...", "Remove ...")

### PR description template

```markdown
## Summary

<!-- What does this PR do? Why is this change needed? -->

## Changes

<!-- Bullet-point list of the concrete changes made -->

## Related Issues

Closes #<issue-number>

## Testing

<!-- How did you test this? Which test files / cases cover it? -->
```

---

## Reporting Bugs

Please use the [GitHub issue tracker](https://github.com/your-org/django-tokenforge/issues/new?template=bug_report.md).

A useful bug report includes:

1. **A minimal reproducible example** — the smallest amount of code that demonstrates the problem
2. **Expected behaviour** — what you expected to happen
3. **Actual behaviour** — what actually happened (include the full traceback)
4. **Environment**:
   - `django-tokenforge` version
   - Python version (`python --version`)
   - Django version (`python -m django --version`)
   - DRF version (`pip show djangorestframework | grep Version`)
   - Database backend
   - Redis version (if relevant)

---

## Requesting Features

Open an [issue](https://github.com/your-org/django-tokenforge/issues/new?template=feature_request.md) and describe:

1. **The problem you need to solve** — "I'm trying to do X but I can't because..."
2. **Your proposed solution** — what the API or behaviour should look like
3. **Alternatives considered** — what workarounds you've tried

We will discuss the approach in the issue before implementation begins. Opening a PR without a prior discussion for non-trivial features risks the PR not being merged.

---

## Security Vulnerabilities

Please **do not** open a public GitHub issue for security vulnerabilities. Follow the process in [SECURITY.md](SECURITY.md).

---

## Release Process

Releases are made by maintainers only. The process is:

1. Update `CHANGELOG.md` — move `[Unreleased]` entries to the new version section with today's date
2. Bump `version` in `pyproject.toml` and `__version__` in `tokenforge/__init__.py`
3. Open and merge a `release/x.y.z` PR
4. Create and push a `vx.y.z` git tag — the CI pipeline publishes to PyPI automatically:
   ```bash
   git tag v1.1.0
   git push origin v1.1.0
   ```

### Versioning policy

We follow [Semantic Versioning](https://semver.org/):

| Change | Version bump |
|---|---|
| New setting, new optional endpoint, new callback | **MINOR** |
| Bugfix, documentation, performance | **PATCH** |
| Breaking change to any public API, endpoint contract, or default settings | **MAJOR** |

Breaking changes are announced in `CHANGELOG.md` with a `### Breaking Changes` subsection and a migration guide.
