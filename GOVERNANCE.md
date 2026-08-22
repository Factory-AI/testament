# Testament governance

Status: Active
Version: 1.0.0
Last updated: 2026-08-21

This document says who may decide what, how a decision becomes final, and how
someone can challenge it. The public record is authoritative. Private messages
do not create project decisions.

## Maintainer authority

The current roster is in [MAINTAINERS.md](MAINTAINERS.md). A person has
maintainer authority only while that roster marks them active. The roles are:

- The lead maintainer appoints and removes maintainers, resolves process
  questions, and approves governance amendments.
- Standards maintainers decide RFCs and changes to normative specifications.
- Release maintainers authorize tags and releases after all required gates
  pass.
- Security maintainers receive private reports and coordinate fixes and
  disclosure.

Maintainers may delegate a bounded task in a public issue or pull request.
Delegation does not transfer voting, release, security-disclosure, or
appointment authority unless the roster is amended.

The lead maintainer may appoint a maintainer after public nomination, evidence
of sustained work, and a five-business-day comment period. Removal uses the
same process, except a maintainer may resign immediately. Emergency suspension
is allowed for compromised credentials or credible harm. The lead must publish
the non-sensitive reason and review the suspension within five business days.

## Decisions and quorum

Routine pull requests use normal review in [CONTRIBUTING.md](CONTRIBUTING.md).
Architecture and normative protocol changes require an RFC or ADR. Governance
changes require an RFC.

The decision owner opens the record as `proposed`, lists affected contracts,
and requests review. After the record reaches `in-review`, the public review
window is at least five business days. A simple majority of eligible,
non-conflicted maintainers in the relevant role decides. Quorum is every
eligible maintainer when there are one or two, or two-thirds when there are
three or more. At least one affirmative vote is always required.

The owner records each vote, the decision date, deciders, reviewers, and
unresolved objections in the indexed record. Silence is not a vote. A tie or
failed quorum leaves the proposal `in-review`; it does not default to
acceptance. Security emergencies may use the emergency rule in
[SECURITY.md](SECURITY.md), followed by public, non-sensitive review.

During initial repository bootstrap, there may be one active maintainer and no
eligible non-author reviewer. That maintainer may decide a foundation record
only when the index marks `bootstrap_exception`, gives a public rationale,
names no reviewer, and sets an expiry. The exception ends when a second
eligible maintainer is appointed or on 2026-09-30, whichever occurs first. It
does not count as independent review and cannot approve a release seal,
critical or high security disposition, or action that requires separation of
duties.

## Conflicts of interest

A maintainer must disclose a personal, employment, financial, or
security-response conflict that a reasonable contributor could see as
affecting the decision. Record authorship is always disclosed. Authorship alone
does not force recusal, but an author cannot be their own independent reviewer.
A conflicted maintainer may explain facts but does not vote, set quorum, close
an appeal, or release work that depends on the decision. The record names the
conflict and recusal without exposing private security details.

If recusals remove quorum, the lead appoints a temporary non-conflicted
maintainer through a public record. If the lead is conflicted, the remaining
eligible maintainer with the longest tenure makes that appointment.

## Escalation and appeals

Start with the record's owner. Post a specific objection, affected requirement,
and requested remedy in the RFC, ADR, issue, or pull request. The owner replies
within five business days.

If unresolved, open an appeal issue titled `Appeal: <record ID>` and link the
decision, objection, evidence, and requested outcome. A non-conflicted
maintainer who did not author the appealed record reviews it. The review may
affirm, remand, or require a superseding record; it may not edit accepted
history. The reviewer records a result within ten business days.

The lead maintainer is the final project appeal. If no eligible reviewer
exists, the appeal remains open and work that depends on the disputed decision
cannot release until an eligible reviewer is appointed. Security reporters use
the private path in [SECURITY.md](SECURITY.md), not a public appeal issue.

## Amendments

Amend this document through an RFC. The RFC must show the old and proposed
rules, transition plan, conflicts, and effect on open decisions. It follows the
normal review and quorum rules. Once accepted, update this document and its
version in the same pull request. Prior text remains available in Git history;
the RFC index records supersession.

## Release authority

Only an active release maintainer may authorize a release. Authorization
requires an identified commit, passing required gates, completed release
evidence for the milestone, no unresolved blocking security finding, and
recorded approval. The release maintainer cannot waive a critical or high
security finding.

For the research foundation, no implementation release may occur before the
immutable candidate, evidence manifest, formal Level 5 report, and external
research seal satisfy the public validation contract. Emergency revocation or
withdrawal may happen immediately to limit harm, but the maintainer must add a
non-sensitive incident record and follow-up decision.

## Maintenance cadence

Active maintainers triage new public issues and pull requests each week. They
review open RFCs, ADRs, and appeals at least every two weeks and the maintainer
roster, supported versions, governance source links, and private-reporting
route every quarter. The security maintainer reviews private reports on the
response schedule in [SECURITY.md](SECURITY.md).

The owner records a missed cadence in the affected issue or record and names a
new review date. Inactive items are not silently closed. An RFC or ADR remains
in its current controlled state until an authorized decision changes it.

## Decision history

Accepted, rejected, and withdrawn RFC and ADR files are historical records. Do
not rewrite them. A later decision uses a new ID and declares `supersedes` in
its immutable text. Only the machine index changes the prior record's lifecycle
status to `superseded` and adds reciprocal `superseded_by` metadata; it retains
the prior file's original header and SHA-256. `make verify-governance` rejects
file drift, broken lineage, unknown status, duplicate IDs, or unindexed
records.
