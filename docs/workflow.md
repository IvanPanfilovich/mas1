# How the workflow fits together

Start with the user’s objective and observable acceptance criteria. The coordinator inspects the sources, identifies uncertainty, chooses Lite, Standard or Assured depth, and decides whether a separate agent would add useful evidence or speed.

A bounded task packet makes delegation reviewable: the child receives a goal, source basis, exact scope, authority, ownership, dependencies, checks and stopping conditions. Reviewers assess plans and actual results; they do not vote to override requirements. Workers implement authorized changes. The coordinator integrates and owns the final decision.

Use parallel read-only work when independent questions are ready. Concurrent writers need explicit resource ownership and agreed shared contracts. Dependent reviews and required consecutive clean passes remain sequential.

When a repair fails, link the finding to its causal root. Preserve lifetime history. Reproduce the failure, test recurrence and a sibling case, check affected behavior, review the result, then obtain the required unchanged-basis follow-up before claiming verified closure. This prevents a small symptom fix from hiding a persistent cause.

The portable adaptation is self-contained in `prompts/MAS1-portable.md`. Exact original rules remain in `prompts/MAS1-v6.1-canonical.md`. Do not silently combine their model/ledger rules. See the [compatibility matrix](compatibility.md).

For an example task packet and final report shape, see [the worked example](../examples/task.md).
