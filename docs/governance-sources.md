# Governance source record

Status: Active
Version: 1.0.0
Last updated: 2026-08-21

These sources support process choices in the governance lifecycle. Testament's
actual rules are the repository documents, not the external sources.

## SRC-GOV-001

- Publisher: GitHub
- Title: Configuring private vulnerability reporting for a repository
- Publication or version date: continuously maintained documentation; accessed
  version 2026-08-21
- URL: <https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository>
- Accessed: 2026-08-21
- Observation: GitHub states that enabled private vulnerability reporting adds
  a **Report a vulnerability** button to the repository Security Advisories
  page and submits a private report.
- Claim supported: the route documented in `SECURITY.md` is GitHub's supported
  private reporting route for this public repository.
- Limitation: notification delivery depends on repository and account
  notification settings.

## SRC-GOV-002

- Publisher: The Linux Foundation and contributors
- Title: Developer Certificate of Origin
- Version: 1.1
- Copyright dates: 2004, 2006
- URL: <https://developercertificate.org/>
- Accessed: 2026-08-21
- Observation: DCO 1.1 asks contributors to certify their right to submit the
  contribution and states that contribution records, including sign-off
  information, are maintained indefinitely and may be redistributed.
- Claim supported: the legal sign-off text and public-record warning in
  `CONTRIBUTING.md`.
- Limitation: a sign-off records the contributor's certification; it is not an
  independent investigation of ownership.

## SRC-GOV-003

- Publisher: RFC Editor
- Author: Scott Bradner
- Title: The Internet Standards Process, Revision 3
- Identifier: RFC 2026, BCP 9
- Publication date: October 1996
- URL: <https://www.rfc-editor.org/rfc/rfc2026.html>
- Accessed: 2026-08-21
- Observation: RFC 2026 describes staged review, open participation, maturity
  status, archival publication, appeals, and replacement of older standards.
- Claim supported: Testament RFCs use explicit states, public review, appeals,
  and supersession instead of editing final history.
- Limitation: Testament is not the IETF and does not claim IETF status. Its
  shorter process and status names are project rules.

## SRC-GOV-004

- Publisher: GitHub ADR organization
- Title: Architectural Decision Records (ADRs)
- Publication date: continuously maintained website; accessed version
  2026-08-21
- URL: <https://adr.github.io/>
- Accessed: 2026-08-21
- Observation: the site defines an ADR as a record of one architecturally
  significant decision and its rationale, with the collection forming a
  decision log.
- Claim supported: Testament keeps one decision and rationale per ADR and
  maintains an indexed decision log.
- Limitation: the site surveys practices rather than imposing a standard;
  Testament's status, digest, and supersession rules are local requirements.

## SRC-GOV-005

- Publisher: Apache Software Foundation
- Title: Apache License, Version 2.0
- Version date: January 2004
- URL: <https://www.apache.org/licenses/LICENSE-2.0.txt>
- Accessed: 2026-08-21
- Observation: section 5 states that intentionally submitted contributions
  are under Apache-2.0 unless the contributor explicitly states otherwise or a
  separate agreement applies.
- Claim supported: contributions accepted into this Apache-2.0 project use its
  project license, alongside the DCO sign-off required by `CONTRIBUTING.md`.
- Limitation: the license text controls. This source record is not legal
  advice and does not replace contributor review of the license and DCO.
