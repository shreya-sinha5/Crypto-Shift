.PHONY: setup lint test demo clean install-java

# ── Setup ──────────────────────────────────────────────────────────────────
setup: install-python install-java install-hooks
	@echo "✅ CryptoShift setup complete"

install-python:
	python -m pip install --upgrade pip
	pip install -e ".[dev,dashboard]"

install-java:
	cd java_helper && mvn clean compile -q

install-hooks:
	pre-commit install

# ── Quality ────────────────────────────────────────────────────────────────
lint:
	ruff check cryptoshift/ tests/
	black --check cryptoshift/ tests/
	python scripts/check_imports.py
	@echo "✅ Lint passed"

format:
	ruff check --fix cryptoshift/ tests/
	black cryptoshift/ tests/

typecheck:
	mypy cryptoshift/

# ── Test ───────────────────────────────────────────────────────────────────
test:
	pytest tests/ -v --tb=short

test-unit:
	pytest tests/unit/ -v --tb=short -m unit

test-integration:
	pytest tests/integration/ -v --tb=short -m integration

test-cov:
	pytest tests/ --cov=cryptoshift --cov-report=html --cov-report=term

# ── Demo ───────────────────────────────────────────────────────────────────
demo:
	@echo "Running CryptoShift demo pipeline..."
	cryptoshift scan --artifacts-dir artifacts/ --json
	cryptoshift enrich --artifacts-dir artifacts/ --json
	cryptoshift transform --artifacts-dir artifacts/ --json
	cryptoshift verify --artifacts-dir artifacts/ --json
	@echo "✅ Demo pipeline complete. Artifacts in artifacts/"

# ── Dashboard ──────────────────────────────────────────────────────────────
dashboard:
	streamlit run cryptoshift/control_centre/app.py

# ── Clean ──────────────────────────────────────────────────────────────────
clean:
	rm -rf build/ dist/ *.egg-info/ .mypy_cache/ htmlcov/ .coverage
	rm -rf artifacts/scan.json artifacts/enriched_cbom.json
	rm -rf artifacts/candidates/*/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	cd java_helper && mvn clean -q 2>/dev/null || true
	@echo "✅ Clean complete"
