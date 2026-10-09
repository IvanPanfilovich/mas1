# Validation scope

`python3 scripts/check.py` runs:

1. Distribution integrity and canonical source checks.
2. Installer and adapter regression tests in isolated temporary directories.
3. The synthetic ledger fixture suite against the production validator.
4. Publicly runnable original ledger regression tests.

The public runner skips two source-machine-bound classes (`LegacyV60AuditMigrationTests`, `PostMigrationRepresentabilityTests`) and two private-project witness tests in `LedgerCoreTests`. Each exclusion and count is printed. The test source is retained so coverage exclusions can be inspected. Missing private evidence is not a passing test. The analyzer regression uses two synthetic temporary cutover manifests instead of private rollout masters, retaining its original rejection assertions.

Tests demonstrate deterministic tooling and installation behavior. They do not establish live account model availability, successful orchestration in Codex/Claude/ChatGPT, original source rollout compliance, runtime sandbox isolation, independent human review, or effectiveness benchmarks. CI uses Linux and Python 3.11/3.12/3.13; local verification is reported in the GitHub release notes.

No real project tasks, credentials, or private witness files are needed for the public checks. Installation tests never modify global Codex/Claude configuration.
