# Example: a bounded engineering task

This example is illustrative. It is not evidence of an executed agent run.

```text
Use MAS1 portable. Delegate when useful.
Goal: Fix duplicate form submissions when the network is slow.
Scope: The checkout form and its existing tests.
Constraints: Preserve API behavior and accessibility. Do not deploy or change billing logic.
Acceptance: A second click cannot create a second pending request; failure restores retry;
keyboard submission follows the same behavior; existing relevant checks pass.
```

The coordinator first inspects the form and API boundary. If this affects actual payment execution or exposes consequential ambiguity, use Assured depth and meet its independence/adjudication requirements before mutation. A harmless UI-only scope may be Standard after evidence resolves that boundary.

A useful Scout packet asks for the submit call path, current pending-state behavior, and relevant tests. A Worker packet owns the exact form/test scope, receives the approved plan and critique disposition, and has no deployment authority. A Reviewer gets the settled diff, requirements, and actual check results and looks for duplicate keyboard submission, failure/retry, stale completion and accessibility regressions.

A final report should say which files changed, why, which checks actually ran and their results, whether a fresh review was independent or internal, and which acceptance evidence remains missing. A plan or illustrative transcript never substitutes for those results.
