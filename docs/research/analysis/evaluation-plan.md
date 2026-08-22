# Analyzer-family evaluation plan

Status: In review

Version: 1.0.0

Validation: `VAL-READY-015`
Machine matrix: [`policy/analyzer-evaluation.json`](../../../policy/analyzer-evaluation.json)

## Scope and decision

This informative plan evaluates deterministic rules, traditional classifiers,
local and external LLMs, ensembles, sequence analyzers, and longitudinal
analysis before production implementation. It does not claim that a passing
analyzer is safe, policy-authoritative, or effective on unknown production
distributions. Analyzer output remains an untrusted assertion.

The machine matrix freezes datasets, splits, metrics, thresholds,
prompt/model/config digests, evidence checks, calibration, nondeterminism,
abstention, cost, injection resistance, and sovereignty attestations. A family
fails if any applicable hard threshold, evidence check, budget, or sovereignty
constraint fails. Critical and high review findings block acceptance.

## Protocol

1. Pin the corpus manifest, labels, evaluator, analyzer/build, binding,
   prompt template and rendered request, model/weights/tokenizer or remote
   identity, configuration, calibration, taxonomy, output schema, and
   sovereignty-attestation digests.
2. Keep development, calibration, and holdout data separate. Paired
   authorized-use twins stay together. Longitudinal splits are entity-disjoint
   and time-forward.
3. Freeze thresholds before holdout execution. Preserve every attempt,
   terminal state, usage, cost, latency, raw structured output, validator
   result, and evidence-reference result.
4. Validate source artifacts and byte ranges before scoring findings. Invalid
   output contributes no finding and remains an `invalid_output` run.
5. Repeat according to each family's nondeterminism class. Report
   distributions rather than selecting a favorable attempt.
6. Recompute metrics independently and route false positives, abstentions, and
   appeals to non-author review.

## Prompt-injection suite

Seeds 1401 through 1420 generate harmless direct, indirect, encoded, split,
multilingual, tool-shaped, delayed cross-session, poisoned-summary, false
citation, and output-schema attacks. The suite treats trace content as hostile
data. A pass requires no ambient capability, secret disclosure, false evidence
acceptance, cross-organization reference, or policy decision. Passing this
finite suite is not proof that prompt injection is prevented.

## Evidence and calibration

Evidence precision is exact because a false source reference undermines the
finding contract. Evidence recall may be lower where abstention is correct.
Calibration uses a disjoint calibration split and reports reliability bins,
sample counts, Brier score, and its limitations. The scikit-learn 1.9.0
calibration guidance notes that Brier score mixes reliability, resolution, and
uncertainty, so Brier alone is not a calibration verdict.

## Sovereignty and cost

Every run binds a compatible signed sovereignty profile. External execution is
limited to explicitly allowed redacted or plaintext fields and records the
destination, region, retention/training declarations, attempts, uncertain
sends, tokens, and cost. There is no provider or model fallback. A provider
declaration is evidence of configuration, not proof of hidden provider
behavior.

## Sources

- National Institute of Standards and Technology, *Adversarial Machine
  Learning: A Taxonomy and Terminology of Attacks and Mitigations*, NIST AI
  100-2 E2025, March 2025, accessed 2026-08-21:
  <https://csrc.nist.gov/pubs/ai/100/2/e2025/final>. Supports lifecycle- and
  capability-aware adversarial evaluation.
- OWASP GenAI Security Project, *LLM01:2025 Prompt Injection*, 2025, accessed
  2026-08-21:
  <https://genai.owasp.org/llmrisk/llm01-prompt-injection/>. Supports direct,
  indirect, obfuscated, split, least-privilege, structured-output, and
  adversarial-test coverage.
- scikit-learn developers, *Probability calibration*, version 1.9.0, accessed
  2026-08-21: <https://scikit-learn.org/stable/modules/calibration.html>.
  Supports reliability analysis, disjoint calibration data, and the stated
  limit of Brier score as a calibration-only measure.

## Review, uncertainty, and open questions

Owner: Eno Reyes (@enoreyes), standards maintainer. Independent analysis,
security, and privacy review is pending. Production label availability,
subgroup coverage, remote provider drift, and production prevalence remain
uncertain. RFC-0007's extension transport and the minimum sample size for
production calibration remain open.
