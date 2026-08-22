.PHONY: setup lint typecheck test test-gate build agent-ready conformance verify-foundation _python-check

PYTHON ?= python3

setup:
	@$(PYTHON) --version
	@echo "Testament foundation uses only Python standard-library tooling."

_python-check:
	@$(PYTHON) -m py_compile scripts/verify_foundation.py tests/test_foundation.py

lint: _python-check
	@$(PYTHON) -m json.tool policy/artifact-licensing.json >/dev/null
	@$(PYTHON) -m json.tool policy/claims.json >/dev/null

typecheck: _python-check

test: test-gate

test-gate:
	@$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v
	@$(MAKE) verify-foundation

build: verify-foundation
	@echo "Static research foundation validated."

agent-ready: verify-foundation
	@echo "Foundation checks are machine-readable and non-interactive."

conformance: verify-foundation
	@echo "Foundation policy conformance passed."

verify-foundation:
	@$(PYTHON) scripts/verify_foundation.py --root .
