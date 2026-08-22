# Unfamiliar-agent guide

Status: Active  
Version: 1.0.0

Start with `make setup`, read [docs/workflows.md](workflows.md), and run
`make agent-ready`. The generated [contract index](../generated/contract-index.json)
points to every core machine contract and its human explanation.

For a bounded change:

1. Copy the issue's acceptance criteria and validation IDs into your plan.
2. Locate the source contract through
   [`policy/repository-contracts.json`](../policy/repository-contracts.json).
3. Select one scoped skill in [`.agents/skills`](../.agents/skills).
4. Add the smallest failing test or coverage rule.
5. Change the source, run `make generate` when generated output is affected,
   and run the focused test.
6. Run the five root gates in the order in [AGENTS.md](../AGENTS.md).
7. Review the diff and preserve all unrelated work.

Do not copy secrets into prompts, commands, fixtures, logs, screenshots, or
commits. Do not infer permission to publish, call external inference, create
cloud resources, or alter repository controls.

If a command fails, parse the JSON object from stderr. It identifies the
criterion, stable code, path, message, and exact remediation. Run
`make doctor`, apply that remediation, and rerun the same entry point. Never
replace the documented service lifecycle or delete unrelated state to make a
gate pass.
