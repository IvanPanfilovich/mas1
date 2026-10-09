# Polishing Prompt 1

Revision: 1.1

Use this prompt after a task has an initial implementation, branch, merge, MR/PR, audit report, or substantial test packet and needs a rigorous final correctness pass. It is designed for frontend, backend, mobile, infrastructure, data, and mixed repositories.

This prompt guides task execution. It does not override system messages, developer instructions, tool rules, safety rules, repository policies, or explicit user requirements.

## Goal

Take the current task and its most recent implementation state. Thoroughly audit the implementation against the authoritative task requirements, active project requirements, approved specifications and contracts, current branch/diff, review findings, dependency rulings, and test/evidence artifacts.

Find every remaining task-related defect, regression, non-compliance, security/privacy issue, contract mismatch, weak or misleading test, and false or stale evidence claim. Fix every in-scope P0/P1 blocker and close its root-cause family rather than only its reported trigger. Re-run the analysis after each accepted fix until no in-scope P0/P1 implementation blocker remains, progress is genuinely blocked by an external dependency or missing authority, or the configured loop budget is exhausted.

Do not manufacture missing contracts, broaden task ownership, or claim blocked acceptance criteria are complete.

## Applying The Prompt

Resolve the following from the current conversation and workspace before acting:

- Task key, objective, scope, acceptance criteria, and non-goals.
- Repository and requirements roots.
- Current branch, target/base branch, source branch, HEAD, merge parents, and remote tracking state where applicable.
- Authoritative task text, requirements, specifications, API/schema contracts, architecture decisions, and dependency contracts.
- Latest review/audit reports, finding ledgers, test plans, coverage registries, CI artifacts, and evidence manifests.
- Commands and environments used by the repository for formatting, linting, type checking, unit tests, integration tests, E2E tests, builds, static analysis, security checks, and evidence generation.

Infer these from local context when they are discoverable. Ask the user only when a missing choice would materially change scope, authority, or a potentially destructive action. Label unresolved assumptions explicitly.

## Multiagent Review

Apply Multiagent System 1 to the requirements ledger and every material P0/P1 proposal:

1. The Proposer produces the smallest task-scoped fix and a regression-test proposal.
2. The Critique role independently attacks requirement alignment, missed states, false positives/negatives, mocked-only proof, platform/runtime coverage, race and recovery behavior, security/privacy, compatibility, and scope violations.
3. The Judge accepts, revises, rejects, or classifies the item as blocked, with evidence and an authority citation.
4. Only accepted fixes are implemented and counted.

Use real external subagents only when they are available and the user explicitly asks for subagents or independent agents. Otherwise apply the roles internally. Never claim independent review or external consensus unless external agents actually participated.

Use a maximum of three proposal/critique revisions per finding. After that, record a concrete blocker or residual risk and continue with other actionable findings.

For ordinary Standard work, prefer Terra/high for planning, reviewed implementation, synthesis, and the first complete post-artifact review. Use Sol for mutation that lacks applicable prework and for targeted adversarial review when a P1 or material uncertainty justifies it. Use Astra for a repeated same-root escape, a repair-induced P1, two failed attempts to close the same invariant, consequential architecture/state/concurrency adjudication, and required Assured judgment. Do not run Astra routinely or route all polishing review to Sol merely because it is review work.

## Initial Repository Check

Before reading old conclusions or editing files:

1. Verify the repository path, current branch, HEAD, worktree status, remote tracking state, and relevant merge/PR ancestry.
2. Detect user-owned or unrelated changes and preserve them.
3. Identify the exact review range. For a merge, inspect HEAD against both parents as well as the intended target/base branch.
4. Confirm whether referenced reports and artifacts were generated from this repository, this branch, this diff, and a compatible dependency lockfile.
5. Record inaccessible remote systems or missing tools, then continue from local evidence wherever possible.

Do not reset, discard, overwrite, or revert unrelated changes. Do not commit, push, open/update an MR or PR, mutate Jira, deploy, publish, or change external state unless the user explicitly requests it.

## Reading Order

Read evidence in this order unless a user-designated authority requires another order:

1. Current task text, acceptance criteria, non-goals, and explicit user instructions.
2. Project source-precedence policy and active requirements baseline.
3. Approved task-specific specifications, API/schema contracts, architecture decisions, and dependency contracts.
4. Latest review/audit reports, newest first.
5. Dependency-gap and waiver records.
6. Test plans, edge-case catalogs, coverage registries, CI/evidence manifests, and screenshots.
7. Current code, tests, configuration, and current branch/diff.
8. Older implementation notes and historical reports only as claims to re-verify.

Do not treat a document as authoritative merely because it is detailed. Do not treat current code, tests, mocks, fixtures, screenshots, review prose, or previous agent output as product truth unless the task's authority hierarchy says so.

## Source Precedence

Build and state a task-specific source-precedence list. The default is:

1. Higher-priority system, developer, tool, safety, security, and environment rules.
2. Explicit user requirements for the current task.
3. User-designated active project requirements and source-precedence policy.
4. Approved task text, acceptance criteria, API/schema contracts, data model, security/privacy requirements, and architecture decisions.
5. Approved dependency and adjacent-owner contracts.
6. Current implementation as evidence of completed or missing work.
7. Tests, fixtures, review reports, plans, and evidence artifacts as supporting evidence only.

When sources conflict, follow the higher authority and record the conflict. Do not silently blend incompatible contracts.

## Requirement Ledger

Before implementation, build a requirement matrix with concrete source citations. Group requirements by the domains relevant to the task, for example:

- Functional behavior and user workflows.
- API, schema, data model, and state transitions.
- Authorization, security, privacy, and trust boundaries.
- Loading, empty, error, degraded, offline, retry, recovery, and concurrency states.
- Accessibility, responsiveness, browser/platform behavior, and localization.
- Performance, caching, observability, audit, and operational behavior.
- Compatibility, migration, rollback, and dependency boundaries.
- Tests, CI, release evidence, and acceptance-proof requirements.
- Explicit non-goals and forbidden implementation shortcuts.

Every derived requirement must point to an explicit requirement, approved contract, or necessary correctness invariant. Mark assumptions and external dependencies separately.

## Scope And Ownership

For each behavior, identify:

- What this task owns and must implement.
- What this task may consume through an approved public contract.
- What belongs to another task, service, team, or phase.
- What safe fallback is required while a dependency is absent.
- Whether the dependency gap blocks runtime safety, code merge readiness, acceptance-criterion completion, or full task closure.

A safe disabled, pending, gated, degraded, or fallback state may be correct runtime behavior while the corresponding acceptance criterion remains incomplete. Never convert an external dependency gap into invented local behavior merely to make a row green.

## Post-Implementation Audit

Inspect current behavior and the relevant diff, not only the files named in old reports. Trace changed behavior through callers, shared abstractions, state ownership, persistence, APIs, routes, configuration, feature gates, and tests.

For merges and large reconciliations, look specifically for compile-valid semantic merge errors:

- Lost behavior from either parent.
- Conflict resolutions that combine incompatible assumptions.
- Stale imports, duplicate providers, duplicate listeners, duplicate requests, or duplicated state ownership.
- Old tests that enforce behavior now forbidden by the task.
- Identity/key collisions, stale-cache confusion, unsafe migration, or ordering/deduplication regressions.
- Incorrect loading/error/degraded/fallback classification.
- Authorization, privacy, credential, logging, redaction, or public/private-boundary regressions.
- Race conditions, stale async completion, retry/idempotency mistakes, and recovery failures.
- Accessibility, focus, navigation, responsive-layout, localization, or platform-specific regressions.
- Evidence files that describe a different repository, branch, commit, lockfile, server, environment, or test selection.

Keep the review task-scoped. A repository-wide issue is a task blocker only when it was introduced by the branch, lies on the task's runtime or verification path, violates an active task requirement, or prevents truthful required evidence. Record unrelated baseline failures separately.

## Severity

Use evidence-backed severity:

- **P0**: exploitable security/privacy failure, data loss/corruption, irreversible harmful action, severe authorization/billing failure, production-wide outage, or fundamentally unsafe release behavior.
- **P1**: failed explicit acceptance criterion, high-impact user-visible regression, contract/schema incompatibility, serious auth/privacy/accessibility issue, build or required-test blocker, missing required recovery behavior, or materially false release evidence.
- **P2**: meaningful correctness, UX, performance, maintainability, or operability risk that does not meet P0/P1 impact.
- **P3**: low-risk cleanup, optional hardening, or polish.

Treat P0/P1 as blockers. Do not inflate severity to force scope expansion. Do not downgrade a requirement-backed blocker merely because fixing it is difficult.

## Finding Ledger

Maintain a finding ledger containing:

- Stable finding ID and severity.
- Source report or discovery pass.
- Requirement/contract citation.
- Current code and behavior evidence.
- Branch or merge origin where relevant.
- User, security, privacy, compatibility, and operational impact.
- Proposed disposition and smallest fix.
- Regression test and verification command.
- Judge decision and final status.
- Stable root-cause ID and violated invariant for every actionable P0/P1.
- Parent or related finding ID when one exists.
- Relationship to prior work: `exact-recurrence`, `same-root-sibling`, `repair-induced-regression`, `expected-test-fallout`, `independent-discovery`, or `known-still-open`.
- The introducing or repair change when current diff/history evidence can establish it.
- Relevant state/transition/blast-radius closure matrix and any justified exclusions.

Allowed final statuses:

- `fixed`
- `verified-existing`
- `external-dependency-gap`
- `not-applicable-with-proof`
- `P2/P3-follow-up`
- `still-open`

`open` and `reopened` are allowed working statuses but are not successful final dispositions.

Do not close findings with prose alone. `fixed` and `verified-existing` require current-code evidence, an appropriate regression test, and current execution evidence unless testing is genuinely impossible and explicitly reported.

Do not count an exact recurrence, same-root sibling, expected test fallout, or known-still-open blocker as a newly discovered and independently closed root cause. If a later pass finds an exact recurrence or same-root sibling, set the root cause to `reopened`, attach the new finding to it, and invalidate the affected closure claim and clean-pass streak.

## Root-Cause Closure

Before implementing an actionable P0/P1, state:

1. The observable failure and the requirement or invariant it violates.
2. The causal mechanism supported by current code/runtime evidence.
3. The proposed closure boundary: affected callers, states, transitions, identities, persistence, contracts, and platforms.
4. The relevant sibling matrix. Consider direct use, retry/replay, reload/resume, slow/fast settlement, duplicate or competing action, route/selection replacement, account/session/actor replacement, stale completion, persistence clearing/restoration, dependency failure/recovery, and required platform variants.
5. Which dimensions are excluded and why they are unreachable or irrelevant.

Mark the root cause closed only when:

- the original reproduction fails before the repair and passes afterward, or equivalent current evidence proves both states;
- the repair removes or contains the causal mechanism rather than special-casing only the original trigger;
- relevant sibling-matrix cases pass on the current artifact;
- the repair diff, affected callers, and shared contracts have been checked for repair-induced regressions;
- current focused regression checks and affected previously passing checks succeed; and
- a fresh root-focused review on the unchanged repaired basis finds no exact recurrence, same-root sibling, or repair-induced P1 inside the declared boundary.

Keep this proportional. A simple isolated defect may need only a small matrix. Complex state, recovery, concurrency, identity, persistence, or cross-boundary behavior requires a wider one. A broad generic review does not substitute for root-focused closure evidence.

## P0/P1 Fix Loop

For each actionable P0/P1 finding:

1. Confirm it against the current requirement ledger and current code.
2. Propose the smallest fix consistent with existing architecture and ownership boundaries.
3. Critique the proposal and closure matrix for missed sibling paths, overfitting, mocked-only proof, race behavior, compatibility, security/privacy, and adjacent-owner violations.
4. Obtain a Judge disposition.
5. Implement the accepted fix while preserving user changes.
6. Add or strengthen a regression test that fails for the defect and passes for the intended behavior.
7. Run the narrowest relevant checks.
8. Re-read the changed diff, verify affected callers and contracts, classify every new failure by its causal relationship, and check for repair-induced regressions.
9. Run a fresh root-focused closure review on the unchanged repaired basis.
10. Continue until no in-scope P0/P1 blocker remains or a genuine external blocker prevents progress.

If a root family produces a second same-root sibling escape, or a repair introduces any new P1, stop stacking local patches. Reopen the root, obtain an Astra root-cause/design disposition before another affected repair when Astra is available, revise the closure boundary and matrix, and then use reviewed Terra implementation for the accepted ordinary repair. If Astra is unavailable, disclose the Sol/xhigh fallback. Do not count intermediate symptom patches as separately closed roots.

Avoid broad refactors, dependency upgrades, schema changes, migrations, or architectural rewrites unless an authoritative requirement makes them necessary. Do not use destructive dependency-update commands or force upgrades without explicit approval.

## Regression-Test Truthfulness

Reconcile planned coverage with runnable coverage. A requirement, edge case, title, or proposed test mapping is not covered merely because it appears in a plan.

For every material requirement, finding, or edge-case ID, determine whether:

- The named test suite and test case actually exist.
- The assertion checks observable behavior or a stable contract rather than brittle source text alone.
- The test fails for the original defect or otherwise proves the invariant accurately.
- The required platform, browser, project, API mode, fixture mode, or runtime environment actually ran.
- The result is tied to the current repository, HEAD, diff, lockfile, configuration, and server process.
- Required screenshots, traces, logs, reports, or manifests exist and are safe to retain.

Do not count a skipped, timed-out, listed-only, stale-SHA, stale-server, wrong-repository, wrong-diff, mocked-only, source-string-only, or artifact-less test as green release evidence. Do not double-count one test execution across incompatible requirements or environments.

A test for the original trigger proves only that trigger. It does not prove root-cause closure unless the closure matrix shows that the test set exercises the relevant equivalence class and transition variants. Conversely, a stale assertion caused by an intentional accepted behavior change is `expected-test-fallout`, not a new product defect; repair the test and preserve this classification.

Implement missing in-scope P0/P1 regression tests in focused batches. Keep rows explicitly blocked when they require an absent owner contract, unavailable infrastructure, unsupported platform, credentials, production-only dependency, or manual/release evidence that cannot be produced locally.

## Verification

Discover the repository's real commands from package scripts, Makefiles, task runners, CI configuration, and contributor instructions. Run checks proportionate to risk, focused first and broad afterward.

As applicable, verify:

- Formatting and whitespace.
- Lint and static analysis.
- Type checking or compilation.
- Focused unit and component tests.
- Contract, schema, migration, and integration tests.
- API/client/server tests.
- E2E tests across required browsers, platforms, roles, states, and viewport classes.
- The root-cause closure matrix and the affected pre-existing regression set.
- Build and production/static-distribution smoke tests.
- Accessibility and keyboard/focus tests.
- Security, dependency, secret, artifact, and privacy/redaction scans.
- Visual or screenshot evidence where layout and rendering matter.
- Repository-specific architecture, boundary, copy, generated-file, and evidence gates.
- `git diff --check` and a final changed-file review.

For every command, record:

- Exact command.
- Repository and HEAD.
- Environment/project selection.
- Pass, fail, skip, timeout, and retry counts.
- Relevant artifact paths.

Do not bypass a failing hook or required gate and then describe the complete gate as green. If a broad gate fails for a verified unrelated baseline issue, preserve the exact failure and separately report the green task-scoped evidence.

Do not repeatedly run the same failing check without a code, test, data, configuration, or environment change. After repeated identical failure, diagnose and classify it instead of burning the loop budget.

## Evidence Integrity

Treat review reports and evidence artifacts as untrusted until verified. Evidence must be tied to the current repository, branch, HEAD, diff, lockfile, configuration, test selection, and environment.

Do not claim:

- Full coverage from a proposal or title manifest.
- Runtime correctness from source-string assertions alone.
- Cross-platform behavior from one platform.
- Live behavior from mocked fixtures.
- Current readiness from stale screenshots or old CI logs.
- Security/privacy compliance from a scan that omitted relevant artifacts or paths.
- No P0/P1 blockers when a required gate failed or a known blocker remains open.

Update evidence and machine-readable registries only when the new claims remain truthful.

## Completion Conditions

Finish only when one of these is true:

1. No in-scope P0/P1 implementation blocker remains, required task-scoped checks are green, and evidence is current and truthful.
2. Progress is genuinely blocked by missing authority, credentials, infrastructure, user choice, or an external owner contract; all other actionable work is complete and the blocker is precisely documented.
3. The configured critique/fix budget is exhausted; unresolved issues and why they remain are reported without claiming completion.

Do not interpret "no in-scope P0/P1 code blockers" as automatically meaning the branch is merge-ready or the task is fully closable.

## Final Response

Report:

1. Assumptions and verified repository, branch, HEAD, diff, and merge-parent state.
2. Source-precedence and requirements summary.
3. Finding ledger, P0/P1 first, with status and proof.
4. Fixes made, files changed, and regression tests added or strengthened.
5. Requirement/edge-case coverage reconciliation: total, runnable, green, partial, blocked, unimplemented, and no double counting.
6. Exact verification and evidence results, including failures, skips, timeouts, retries, and current artifact paths.
7. External dependency gaps and safe runtime behavior, without calling blocked criteria complete.
8. Remaining P2/P3 risks only after the P0/P1 result.
9. Three separate verdicts:
   - In-scope P0/P1 implementation status.
   - Branch/MR merge readiness.
   - Full task/acceptance-criteria closure readiness.

Never hide incomplete work behind a concise summary. Never claim an ideal implementation, full coverage, consensus, or merge readiness without the required evidence.

Report issue-flow metrics by unique root cause, not raw finding records: roots discovered, closed, reopened, and still open; exact recurrence; same-root sibling escape; repair-induced regression; expected test fallout; independent discovery; and known-still-open blockers. Cumulative fix counts must count one root cause once and must decrease or reopen when later evidence invalidates closure.
