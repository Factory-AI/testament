.PHONY: setup lint typecheck test test-gate build agent-ready conformance generate-corpus verify-corpus verify-foundation verify-governance verify-research _python-check

PYTHON ?= python3

setup:
	@$(PYTHON) --version
	@echo "Testament foundation uses only Python standard-library tooling."

_python-check:
	@$(PYTHON) -m py_compile scripts/generate_corpus.py scripts/verify_corpus.py scripts/verify_foundation.py scripts/verify_governance.py scripts/verify_research.py tests/test_corpus.py tests/test_foundation.py tests/test_governance.py tests/test_research_registry.py

lint: _python-check
	@$(PYTHON) -m json.tool policy/artifact-licensing.json >/dev/null
	@$(PYTHON) -m json.tool policy/abuse-misuse-research.json >/dev/null
	@$(PYTHON) -m json.tool policy/claims.json >/dev/null
	@$(PYTHON) -m json.tool policy/naming-clearance.json >/dev/null
	@$(PYTHON) -m json.tool policy/research-manifest.json >/dev/null
	@$(PYTHON) -m json.tool policy/threat-privacy-sovereignty.json >/dev/null
	@$(PYTHON) -m json.tool policy/trace-landscape.json >/dev/null
	@$(PYTHON) -m json.tool docs/research/corpus/manifest.json >/dev/null
	@$(PYTHON) -m json.tool schemas/abuse-misuse-research.schema.json >/dev/null
	@$(PYTHON) -m json.tool schemas/naming-clearance.schema.json >/dev/null
	@$(PYTHON) -m json.tool schemas/research-manifest.schema.json >/dev/null
	@$(PYTHON) -m json.tool schemas/threat-privacy-sovereignty.schema.json >/dev/null
	@$(PYTHON) -m json.tool schemas/trace-landscape.schema.json >/dev/null
	@$(PYTHON) -m json.tool schemas/synthetic-corpus.schema.json >/dev/null

typecheck: _python-check

test: test-gate

test-gate:
	@$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v
	@$(MAKE) verify-foundation
	@$(MAKE) verify-governance
	@$(MAKE) verify-research
	@$(MAKE) verify-corpus

build: verify-foundation
	@$(MAKE) verify-governance
	@$(MAKE) verify-research
	@$(MAKE) verify-corpus
	@echo "Static research foundation validated."

agent-ready: verify-foundation
	@$(MAKE) verify-governance
	@$(MAKE) verify-research
	@$(MAKE) verify-corpus
	@echo "Foundation checks are machine-readable and non-interactive."

conformance: verify-foundation
	@$(MAKE) verify-governance
	@$(MAKE) verify-research
	@$(MAKE) verify-corpus
	@echo "Foundation policy conformance passed."

verify-foundation:
	@$(PYTHON) scripts/verify_foundation.py --root .

verify-governance:
	@$(PYTHON) scripts/verify_governance.py --root .

verify-research:
	@$(PYTHON) scripts/verify_research.py --root .

generate-corpus:
	@$(PYTHON) scripts/generate_corpus.py --root . --write

verify-corpus:
	@$(PYTHON) scripts/verify_corpus.py --root .
