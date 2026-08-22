.PHONY: setup dev dev-stop lint typecheck test test-gate build agent-ready conformance generate generate-corpus migrate release rollback doctor incident verify-corpus verify-foundation verify-governance verify-readiness verify-research _python-check

PYTHON ?= python3

setup:
	@$(PYTHON) scripts/workflow.py setup --root .

dev: setup
	@TESTAMENT_POSTGRES_PORT=5440 docker compose up -d postgres

dev-stop:
	@TESTAMENT_POSTGRES_PORT=5440 docker compose stop postgres

_python-check:
	@$(PYTHON) -m py_compile scripts/generate_corpus.py scripts/verify_corpus.py scripts/verify_foundation.py scripts/verify_governance.py scripts/verify_readiness.py scripts/verify_research.py scripts/workflow.py tests/test_corpus.py tests/test_foundation.py tests/test_governance.py tests/test_readiness.py tests/test_research_registry.py

lint: _python-check
	@$(PYTHON) -m json.tool policy/artifact-licensing.json >/dev/null
	@$(PYTHON) -m json.tool policy/abuse-misuse-research.json >/dev/null
	@$(PYTHON) -m json.tool policy/architecture.json >/dev/null
	@$(PYTHON) -m json.tool policy/claims.json >/dev/null
	@$(PYTHON) -m json.tool policy/naming-clearance.json >/dev/null
	@$(PYTHON) -m json.tool policy/readiness.json >/dev/null
	@$(PYTHON) -m json.tool policy/repository-contracts.json >/dev/null
	@$(PYTHON) -m json.tool policy/research-manifest.json >/dev/null
	@$(PYTHON) -m json.tool policy/threat-privacy-sovereignty.json >/dev/null
	@$(PYTHON) -m json.tool policy/toolchain.json >/dev/null
	@$(PYTHON) -m json.tool policy/trace-landscape.json >/dev/null
	@$(PYTHON) -m json.tool docs/research/corpus/manifest.json >/dev/null
	@$(PYTHON) -m json.tool generated/contract-index.json >/dev/null
	@$(PYTHON) -m json.tool schemas/actionable-error.schema.json >/dev/null
	@$(PYTHON) -m json.tool schemas/abuse-misuse-research.schema.json >/dev/null
	@$(PYTHON) -m json.tool schemas/naming-clearance.schema.json >/dev/null
	@$(PYTHON) -m json.tool schemas/repository-contracts.schema.json >/dev/null
	@$(PYTHON) -m json.tool schemas/research-manifest.schema.json >/dev/null
	@$(PYTHON) -m json.tool schemas/threat-privacy-sovereignty.schema.json >/dev/null
	@$(PYTHON) -m json.tool schemas/toolchain.schema.json >/dev/null
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
	@$(MAKE) verify-readiness

build: verify-foundation
	@$(MAKE) verify-governance
	@$(MAKE) verify-research
	@$(MAKE) verify-corpus
	@$(MAKE) verify-readiness
	@echo "Static research foundation validated."

agent-ready: verify-foundation
	@$(MAKE) verify-governance
	@$(MAKE) verify-research
	@$(MAKE) verify-corpus
	@$(MAKE) verify-readiness

conformance: verify-foundation
	@$(MAKE) verify-governance
	@$(MAKE) verify-research
	@$(MAKE) verify-corpus
	@$(MAKE) verify-readiness
	@echo "Foundation policy conformance passed."

generate: generate-corpus
	@$(PYTHON) scripts/verify_readiness.py --root . --write-index

migrate:
	@$(PYTHON) scripts/workflow.py migrate --root .

release:
	@$(PYTHON) scripts/workflow.py release --root .

rollback:
	@$(PYTHON) scripts/workflow.py rollback --root .

doctor:
	@$(PYTHON) scripts/workflow.py doctor --root .

incident:
	@$(PYTHON) scripts/workflow.py incident --root .

verify-foundation:
	@$(PYTHON) scripts/verify_foundation.py --root .

verify-governance:
	@$(PYTHON) scripts/verify_governance.py --root .

verify-readiness:
	@$(PYTHON) scripts/verify_readiness.py --root .

verify-research:
	@$(PYTHON) scripts/verify_research.py --root .

generate-corpus:
	@$(PYTHON) scripts/generate_corpus.py --root . --write

verify-corpus:
	@$(PYTHON) scripts/verify_corpus.py --root .
