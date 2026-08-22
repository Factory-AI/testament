# Abuse and misuse research

Status: Informative draft

Version: 0.2.0

Deliverable: `RES-STUDY-ABUSE-MISUSE-001`

Validation: `VAL-READY-009`

Research date: 2026-08-21

This study maps nine harm domains to observable signals, timing, legitimate
counterexamples, review, appeal, and research gaps. A signal starts an inquiry.
It is not a finding.

The complete source and harm matrix is
[`policy/abuse-misuse-research.json`](../../../policy/abuse-misuse-research.json).
Its [JSON Schema](../../../schemas/abuse-misuse-research.schema.json) and the
research verifier require every domain, all three timing classes, an
authorized-use twin, false-positive factors, a reviewer path, limitations,
open questions, and dated sources.

## Timing model

Online evidence is available during the current interaction and can inform a
bounded real-time decision. It has the least context.

Nearline evidence arrives after short aggregation or enrichment, usually
minutes to hours later. It can support containment or queued review, but it
cannot change an interaction that already finished.

Offline evidence comes from longitudinal analysis, incident work, external
reports, evaluation, or adjudication. It is slower and may be stronger, though
it is still incomplete and can inherit bad identifiers or biased reports.

These are availability classes, not fixed latency budgets. A deployment must
record the actual event time, decision time, enrichment time, and review time.

## Harm matrix

| Risk | Online lead | Nearline lead | Offline lead | Authorized-use twin | Reviewer |
| --- | --- | --- | --- | --- | --- |
| Cyber | Live-target context plus exploit or execution-capable tool action | Sequence moves from reconnaissance toward persistence | Incident or threat evidence confirms authorization boundary and impact | Penetration test, CTF, defensive research, incident response | Security-abuse analyst; escalate to incident or product security |
| CBRN | Harmful optimization, acquisition, scale, concealment, or hazardous tool action | Ambiguous requests compose into an operational workflow | Qualified expert assesses real capability uplift | Biosafety, public health, nonproliferation, emergency response | Specialist reviewer; escalate to a qualified CBRN expert |
| Fraud | Impersonation, secrecy, urgency, payment or identity action | Repeated templates, changed beneficiaries, linked synthetic identities | Victim reports, chargebacks, verified impersonation, case linkage | Fraud simulation, support, authorized marketing | Fraud operations; escalate to accountable fraud-risk owner |
| Compromised accounts | Authentication shift or sensitive action without expected step-up | Session, recovery, token, privilege, and access anomalies align | Owner report or forensics confirms the compromise window | Travel, VPN, new device, automation, emergency access | Identity analyst; escalate to incident response or tenant admin |
| Model extraction | Boundary probing or unauthorized artifact access | Adaptive, high-coverage queries coordinate across accounts | Query analysis, forensics, or artifact evidence supports extraction | Licensed distillation, benchmarking, regression and red-team tests | Abuse analyst; escalate to model security and product authority |
| Evasion | Encoding, fragmentation, indirection, or transformed retry | Paraphrases and account changes converge on the same outcome | Evaluation finds a repeatable detector blind spot | Accessibility, internationalization, robustness testing | Trust-and-safety analyst; escalate to detector owner |
| Prompt injection | Untrusted instructions redirect an agent or tool outside its boundary | Retrieved items compose into anomalous control flow | Pinned sandbox replay reproduces the path and impact | Security test, quoted instruction, code sample, evaluation fixture | Application security; escalate to product and affected tool/data owner |
| Insider risk | Privileged action exceeds role, ticket, purpose, or dual control | Access and privilege patterns diverge from current duties | Multidisciplinary investigation adds approvals, role history, and impact | On-call response, audit, migration, e-discovery, support | Governed insider-risk analyst; multidisciplinary escalation |
| Coordinated actors | Strong campaign identifier or state passes across cooperating agents | Accounts synchronize targets, infrastructure, scripts, or beneficiaries | Graph and human review test campaign and innocent explanations | Teams, classrooms, open-source work, shared enterprise networks | Campaign analyst; escalate to trust-and-safety with privacy/legal input |

Each row in the JSON matrix also states what would make the lead a false
positive, what evidence the reviewer needs, how an appeal reaches a separate
reviewer, and what remains unknown.

## Counterexamples matter

The same observable sequence can mean different things:

- A vulnerability chain may be an authorized penetration test.
- Specific biological language may come from a biosafety review.
- Repeated payment messages may be legitimate customer communication.
- New geography may be travel or a corporate VPN, not account takeover.
- A dense query grid may be a licensed benchmark.
- Homoglyphs or unusual spacing may support accessibility or another language.
- A document can quote hostile instructions without controlling the agent.
- Bulk export may be an approved audit or incident response.
- Synchronized accounts may be a class, team, or shared company network.

Context does not make every action acceptable. It does mean that content,
volume, anomaly, or graph proximity alone is too weak for a consequential
finding.

## Human review

The first reviewer needs domain training and the minimum evidence needed to
test the lead. The review display should include original evidence, provenance,
time, detector/model/policy versions, uncertainty, related events, the stated
authorization, and evidence against the finding.

Detection and adjudication stay separate. CBRN, employment, legal,
cross-account, and high-impact account actions need a qualified specialist or
accountable authority. A reviewer should not be asked to infer a complete
incident from a score and a generated summary.

Prompt injection also applies to review systems. Untrusted captured content
must not become system instructions, trigger tools, or silently alter the
review record.

## Appeals and correction

A useful appeal route has four properties:

1. the affected party receives a reason, except where a documented safety,
   security, or legal constraint prevents disclosure;
2. the route remains available outside a session suspected of compromise;
3. a reviewer who did not make the initial decision checks identity,
   authorization, role, language, accessibility, and linkage errors; and
4. correction reaches dependent findings, campaign edges, and access state.

An appeal can sustain, narrow, or reverse a decision. The record should show
the evidence and reason either way. Lack of an appeal is weak validation:
people may not receive notice, may lose access to the appeal channel, or may
not trust it.

## False positives

One overall precision number hides the cases that matter. Evaluation should
split results by domain, timing, detector version, language, accessibility
context, account segment, and reviewer outcome. Successful appeals and sampled
negatives are evidence, not embarrassing exceptions to discard.

Online evidence often warrants abstention, confirmation, least-privilege tool
behavior, or queued review rather than an irreversible action. Nearline and
offline analysis can add context, but only if the system retained provenance
and the original representation.

Behavioral baselines and coordination graphs deserve special care. They can
encode geography, disability, work schedule, organization, or community
membership. One bad identifier can spread a false finding across a graph.

## Sources and disagreements

The matrix links each claim to public source material from NIST, CISA, FTC,
FBI, MITRE ATT&CK/ATLAS, OWASP, the European Union, and provider safety
frameworks.

The sources do not define one shared severity scale or reviewer workflow.
Provider preparedness frameworks focus on frontier capability and safeguards.
NIST organizes adversarial behavior and risk management. Government consumer
and identity guidance describes known abuse patterns and controls. OWASP
focuses on application weaknesses. Those views overlap, but none establishes a
universal policy decision for a particular user.

This study therefore records an inference separately: evidence should preserve
timing, provenance, authorization, and counterevidence so a responsible owner
can make a scoped decision. It does not infer that the presence of a source
category proves harm.

## Open questions

1. What minimum evidence supports appeal without exposing other users,
   hazardous details, secrets, or active incident data?
2. How should lawful authorization be attested across organizations without
   disclosing sensitive test scope?
3. Which online actions are reversible enough to use under uncertainty?
4. How should corrections propagate through campaign graphs and longitudinal
   findings?
5. What retention period allows meaningful appeal without building a
   disproportionate identity, workforce, or behavior archive?
6. How can replay stay deterministic when models, retrieval sources, tools,
   and policies change?

## Limits

This study is informative research, not enforcement policy, legal advice, or a
catalog of abuse instructions. It deliberately avoids operational harmful
detail.

Most signals are dual use. External reports can be false. Models and reviewers
can be manipulated. Missing context may never become available, and more data
can increase privacy and sovereignty risk rather than settle a case.

No system can provide perfect safety. Testament does not automatically enforce
decisions.
