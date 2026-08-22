# Testament security policy

Status: Active
Version: 1.0.0
Last updated: 2026-08-21

Thank you for reporting security problems privately. Do not put vulnerability
details, exploit code, secrets, or affected-user data in a public issue.

## Supported versions

Testament has not published a supported release. Reports against the current
`main` branch and the public research or governance artifacts are accepted.
Once releases exist, this table will identify the supported lines.

| Version | Supported |
| --- | --- |
| No release yet | No production support |
| Current `main` | Security reports accepted |

## Private reporting

Open the repository's
[Security Advisories page](https://github.com/Factory-AI/testament/security/advisories)
and select **Report a vulnerability**. GitHub private vulnerability reporting
is enabled. Include:

- the affected commit, file, endpoint, or version;
- impact and the conditions needed to reproduce it;
- minimal reproduction steps or a harmless proof;
- whether you believe anyone is actively exposed;
- your preferred contact and disclosure credit.

Use synthetic data. Do not include customer traces, personal data, live
credentials, private keys, or material you are not allowed to share. If the
form is temporarily unavailable, keep the report private and retry through the
same Security Advisories page. A public issue may say only that the private
reporting channel is unavailable; it must contain no vulnerability detail.

## Response expectations

A security maintainer will aim to:

- acknowledge a report within three business days;
- provide an initial severity and scope assessment within seven business days;
- send an update at least every seven calendar days while work is active;
- agree on a disclosure date after impact, fix availability, and deployment
  time are understood.

These are response targets, not a promise that every report can be fixed on a
fixed schedule. The private advisory is the record for status, decisions,
credits, and disclosure.

## Coordinated disclosure

The reporter and security maintainer agree on what can be published and when.
The project may ask for time to develop, validate, and distribute a fix.
Reporters may decline credit. If the parties disagree, either may request the
appeal path below while keeping technical details private.

When disclosure is ready, the security maintainer publishes an advisory that
states affected versions, impact, mitigations, fixed versions or commits,
credits, and relevant CVE information. Accepted RFC, ADR, audit, and release
history is not rewritten to hide the event.

## Safe harbor

The project considers research authorized when it follows this policy, is
performed in good faith, and is intended to improve security. The project will
not initiate or support legal action for accidental, good-faith violations
that are reported promptly and corrected on request.

This safe harbor does not authorize privacy violations, social engineering,
denial of service, persistence, data destruction, credential use beyond the
minimum needed to prove a finding, access to another person's data, or
exfiltration. Stop when you have enough evidence. Respect third-party terms and
law; this project cannot authorize research against systems it does not own.
If you are unsure whether a test is safe, ask in a private report before
running it.

## Emergency escalation

For active exploitation, exposed signing or release credentials, or a
vulnerability likely to cause immediate serious harm, submit a private report
and begin its title with `[URGENT]`. State what is happening now and the least
disruptive containment step.

The security maintainer may privately coordinate an emergency patch,
credential revocation, release withdrawal, or temporary feature disablement.
Two non-conflicted maintainers approve when available. If delay would increase
harm, one security maintainer may act and must request retrospective review
within two business days. Public follow-up omits exploit details until
coordinated disclosure.

## Security appeals

Reply in the private advisory and ask for review by a non-conflicted security
maintainer who did not make the disputed decision. If none exists, the lead
appoints one under the conflict rules in [GOVERNANCE.md](GOVERNANCE.md). The
reviewer records the result in the advisory. Do not move a security appeal to
a public issue before coordinated disclosure.

## Source for the reporting route

GitHub documents that enabling private vulnerability reporting gives
researchers a structured private form on a public repository's Security
Advisories page. The full source record and access date are in
[docs/governance-sources.md](docs/governance-sources.md).
