# RFC-0001: Three-business-day governance review

ID: RFC-0001
Status: accepted
Version: 1.0.0
Decision date: 2026-08-21
Supersedes: None
Superseded by: None
Owners: @enoreyes
Reviewers: @enoreyes

## Summary

Require a three-business-day public review for governance and normative RFCs.

## Motivation

The project needed a concrete review window before accepting decisions.

## Scope and non-goals

This covered RFC review time only. It did not set release or security response
times.

## Proposed contract

An RFC in `in-review` remains open for at least three business days before a
decision.

## Compatibility and migration

The rule affected process only. Open RFCs would use the new minimum.

## Security and privacy

Longer private coordination remained available for embargoed security work.
No private report content would enter the public RFC.

## Alternatives

No minimum was rejected because it made public participation unpredictable.
Five business days was considered too slow at repository bootstrap.

## Validation

The lifecycle guide and machine index recorded the review rule, status, and
decision.

## Decision

Accepted on 2026-08-21 by @enoreyes to establish an initial window. The
single-maintainer bootstrap exception applied; there was no independent
reviewer.

## Supersession

None at publication. A successor must declare this RFC's ID without changing
this file.
