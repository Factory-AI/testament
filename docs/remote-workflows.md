# Remote workflows and maintenance

Status: Active
Version: 1.0.0
Machine contract: [`policy/remote-workflows.json`](../policy/remote-workflows.json)

## Contribution metadata

The structured issue form and pull request template require problem, scope,
non-goals, acceptance, validation, dependencies, risk, rollout,
observability, documentation, compatibility, generated-artifact, and
agent-authorship evidence. The `Metadata / validate` check reruns when a
record opens, changes, synchronizes, or reopens. Empty stable sections fail
with criterion `VAL-READY-025`, a location, and an edit command.

Every contribution after the recorded history boundary requires a Developer
Certificate of Origin `Signed-off-by` trailer. Historical prerequisite commits
remain attributable but are not rewritten. `DCO / signoff` is a required
remote check.

## Protected main

The production ruleset targets only `main`. It requires a pull request, one
approval, CODEOWNERS approval, stale-approval dismissal, approval after the
latest push, resolved conversations, strict status checks, and the DCO check.
It blocks force-pushes and deletion.

There is no standing bypass. During the single-maintainer bootstrap only, an
administrator may add a pull-request-only bypass actor for a named, public,
time-bounded operation after normal checks pass. The audit record must state
the reason, start, expiry, pull request, and checks. The actor entry is removed
immediately after use. This never authorizes force-pushing or deleting `main`,
granting access, appointing a maintainer, or weakening a Testament check.

## CI and security

Quality runs the declared local gates on pull requests, protected pushes,
weekly schedules, manual requests, and published releases. Security runs
CodeQL and dependency review with immutable, signature-verified action
commits. The action review registry records the exact release and runtime for
each allowed pin. Every selected release was public for at least seven days
before review. GitHub-authored JavaScript actions use Node.js 24.
Workflows declare minimal permissions, do not use `pull_request_target`, and
retain machine-readable quality artifacts for 14 days. Secret scanning, push
protection, dependency alerts, security updates, code scanning, and private
vulnerability reporting are repository controls.

Run `make verify-remote-workflows` for static workflow, pin, permission,
trigger, template, ownership, and maintenance checks. Run
`make verify-publication` before publication. The latter resolves the
Testament Git root and scans only added or modified Testament paths. It rejects
path escape, ignores unrelated repositories, and blocks genuine findings in
Testament. It does not disable or bypass Droid Shield or GitHub secret
scanning. A finding exception must bind the exact repository path, line,
finding class, match digest, rationale, and expiry. The only current exception
is AWS's documented `EXAMPLE` canary used to prove the corpus scanner fails.

## Agent-actionable maintenance

The weekly maintenance workflow owns one deduplicated issue per stable marker.
It preserves the unresolved USPTO and WIPO evidence and requires dated,
attestable, qualified trademark review before commercial launch, filing, or
broader distribution. That record remains non-blocking for the current
open-source mission unless new evidence makes the name unusable.

A separate record tracks the 2026-09-30 single-maintainer bootstrap expiry.
The automation changes no repository access and keeps sole-maintainer status
truthful. Expired evidence receives zero readiness credit.

Quality failures create or update one owned issue with the stable criterion,
run, artifact, cause, and remediation. A separate `workflow_run` workflow uses
only trusted default-branch reporting code, so untrusted pull-request code
never receives an issue-write token. The issue closes only when a later
protected-main Quality run verifies recovery. The deliberate failure input
exists only to prove this path safely; rerun with
`deliberate_failure=false`.
