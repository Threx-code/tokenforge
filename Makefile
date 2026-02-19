# Format & lint
run-ruff:
	pipx run ruff format .
	pipx run ruff check .

# Type check
run-mypy:
	PYTHONPATH=. .venv/bin/mypy tokenforge/

# Run tests
run-tests:
	PYTHONPATH=. .venv/bin/pytest --cov=tokenforge --cov-report=term-missing -v

# Verify the package builds cleanly
build-package:
	.venv/bin/pip install build setuptools wheel --quiet
	.venv/bin/python -m build --wheel --no-isolation

# Create venv and install all dev dependencies
setup-dev:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev,redis]"
