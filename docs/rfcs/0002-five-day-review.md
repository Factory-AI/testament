# RFC-0002: Five-business-day governance review

ID: RFC-0002
Status: accepted
Version: 1.0.0
Decision date: 2026-08-21
Supersedes: RFC-0001
Superseded by: None
Owners: @enoreyes
Reviewers: @enoreyes

## Summary

Require at least five business days of public review for governance and
normative RFCs.

## Motivation

A full working week gives contributors in different schedules and time zones a
predictable chance to comment. RFC-0001 allowed only three business days.

## Scope and non-goals

This sets the ordinary minimum review window. It does not shorten security
embargoes, incident response, contribution review, or an explicit longer
window.

## Proposed contract

The owner marks the RFC `in-review` and records that date. Maintainers do not
make a final decision until five business days have elapsed. The emergency
security procedure may act sooner to limit harm and requires retrospective
review.

## Compatibility and migration

Open governance and normative RFCs use the five-day minimum. Completed
decisions are not reopened solely because they used the earlier rule.

## Security and privacy

The rule applies only to public, non-sensitive material. Private vulnerability
details stay in the security advisory. Emergency action remains available.

## Alternatives

Three days was too short. Ten days would improve notice but would slow routine
foundation decisions without current evidence of need.

## Validation

`make verify-governance` checks this record's status, metadata, digest, and
reciprocal link to RFC-0001. A reviewer manually confirms the rule appears in
`GOVERNANCE.md`.

## Decision

Accepted on 2026-08-21 by @enoreyes. The project was at bootstrap with one
active maintainer, so the bounded bootstrap exception applied and there was no
independent reviewer. The limitation is recorded rather than presented as
independent consensus.

## Supersession

This RFC supersedes RFC-0001. The RFC-0001 file remains unchanged; its index
entry points to this record.
