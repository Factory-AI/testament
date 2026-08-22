.PHONY: setup dev dev-stop lint typecheck test test-gate build agent-ready conformance generate generate-analyzer-evaluation generate-analyzer-metrics generate-corpus migrate release rollback doctor incident verify-analyzer-evaluation verify-analyzer-metrics verify-claims verify-corpus verify-foundation verify-governance verify-prototypes verify-readiness verify-research _python-check

PYTHON ?= python3

setup:
	@$(PYTHON) scripts/workflow.py setup --root .

dev: setup
	@TESTAMENT_POSTGRES_PORT=5440 docker compose up -d postgres

dev-stop:
	@TESTAMENT_POSTGRES_PORT=5440 docker compose stop postgres

_python-check:
	@$(PYTHON) -m py_compile scripts/evaluate_analyzer_metrics.py scripts/generate_analyzer_evaluation.py scripts/generate_analyzer_metrics.py scripts/generate_corpus.py scripts/run_prototypes.py scripts/verify_analyzer_evaluation.py scripts/verify_analyzer_metrics.py scripts/verify_claims.py scripts/verify_corpus.py scripts/verify_foundation.py scripts/verify_governance.py scripts/verify_prototypes.py scripts/verify_readiness.py scripts/verify_research.py scripts/workflow.py tests/test_analyzer_evaluation.py tests/test_analyzer_metrics.py tests/test_claims_and_boundaries.py tests/test_corpus.py tests/test_foundation.py tests/test_governance.py tests/test_prototypes.py tests/test_readiness.py tests/test_research_registry.py

lint: _python-check
	@$(PYTHON) -m json.tool policy/artifact-licensing.json >/dev/null
	@$(PYTHON) -m json.tool policy/abuse-misuse-research.json >/dev/null
	@$(PYTHON) -m json.tool policy/analyzer-evaluation.json >/dev/null
	@$(PYTHON) -m json.tool policy/analyzer-metric-registry.json >/dev/null
	@$(PYTHON) -m json.tool policy/architecture.json >/dev/null
	@$(PYTHON) -m json.tool policy/claims-ledger.json >/dev/null
	@$(PYTHON) -m json.tool policy/claims.json >/dev/null
	@$(PYTHON) -m json.tool policy/normative-sources.json >/dev/null
	@$(PYTHON) -m json.tool policy/prototype-claims.json >/dev/null
	@$(PYTHON) -m json.tool policy/naming-clearance.json >/dev/null
	@$(PYTHON) -m json.tool policy/readiness.json >/dev/null
	@$(PYTHON) -m json.tool policy/repository-contracts.json >/dev/null
	@$(PYTHON) -m json.tool policy/research-manifest.json >/dev/null
	@$(PYTHON) -m json.tool policy/threat-privacy-sovereignty.json >/dev/null
	@$(PYTHON) -m json.tool policy/toolchain.json >/dev/null
	@$(PYTHON) -m json.tool policy/trace-landscape.json >/dev/null
	@$(PYTHON) -m json.tool docs/research/corpus/manifest.json >/dev/null
	@$(PYTHON) -m json.tool docs/research/analysis/injection-manifest.json >/dev/null
	@$(PYTHON) -m json.tool docs/research/analysis/metric-golden-vectors.json >/dev/null
	@$(PYTHON) -m json.tool docs/research/analysis/split-manifest.json >/dev/null
	@$(PYTHON) -m json.tool docs/research/benchmarks/reproduction.json >/dev/null
	@$(PYTHON) -m json.tool generated/contract-index.json >/dev/null
	@$(PYTHON) -m json.tool schemas/actionable-error.schema.json >/dev/null
	@$(PYTHON) -m json.tool schemas/abuse-misuse-research.schema.json >/dev/null
	@$(PYTHON) -m json.tool schemas/claims-ledger.schema.json >/dev/null
	@$(PYTHON) -m json.tool schemas/naming-clearance.schema.json >/dev/null
	@$(PYTHON) -m json.tool schemas/normative-sources.schema.json >/dev/null
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
	@$(MAKE) verify-claims
	@$(MAKE) verify-corpus
	@$(MAKE) verify-prototypes
	@$(MAKE) verify-analyzer-evaluation
	@$(MAKE) verify-readiness

build: verify-foundation
	@$(MAKE) verify-governance
	@$(MAKE) verify-research
	@$(MAKE) verify-claims
	@$(MAKE) verify-corpus
	@$(MAKE) verify-prototypes
	@$(MAKE) verify-analyzer-evaluation
	@$(MAKE) verify-readiness
	@echo "Static research foundation validated."

agent-ready: verify-foundation
	@$(MAKE) verify-governance
	@$(MAKE) verify-research
	@$(MAKE) verify-claims
	@$(MAKE) verify-corpus
	@$(MAKE) verify-prototypes
	@$(MAKE) verify-analyzer-evaluation
	@$(MAKE) verify-readiness

conformance: verify-foundation
	@$(MAKE) verify-governance
	@$(MAKE) verify-research
	@$(MAKE) verify-claims
	@$(MAKE) verify-corpus
	@$(MAKE) verify-prototypes
	@$(MAKE) verify-analyzer-evaluation
	@$(MAKE) verify-readiness
	@echo "Foundation policy conformance passed."

generate:
	@$(MAKE) generate-corpus
	@$(MAKE) generate-analyzer-evaluation
	@$(MAKE) generate-analyzer-metrics
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

verify-claims:
	@$(PYTHON) scripts/verify_claims.py --root .

verify-prototypes:
	@$(PYTHON) scripts/verify_prototypes.py --root . --criterion VAL-READY-014

verify-analyzer-evaluation:
	@$(PYTHON) scripts/verify_prototypes.py --root . --criterion VAL-READY-015
	@$(PYTHON) scripts/verify_analyzer_evaluation.py --root .
	@$(MAKE) verify-analyzer-metrics

verify-analyzer-metrics:
	@$(PYTHON) scripts/verify_analyzer_metrics.py --root .

verify-readiness:
	@$(PYTHON) scripts/verify_readiness.py --root .

verify-research:
	@$(PYTHON) scripts/verify_research.py --root .

generate-corpus:
	@$(PYTHON) scripts/generate_corpus.py --root . --write

generate-analyzer-evaluation:
	@$(PYTHON) scripts/generate_analyzer_evaluation.py --root . --write

generate-analyzer-metrics:
	@$(PYTHON) scripts/generate_analyzer_metrics.py --root . --write

verify-corpus:
	@$(PYTHON) scripts/verify_corpus.py --root .
