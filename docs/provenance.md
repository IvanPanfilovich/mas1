# Version and provenance

Latest local protocol found: **MAS1 v6.1**, declared in the source prompt (its historical filename ends in `v6.md`). Public distribution **6.1.0** packages that protocol; it does not invent a protocol revision 6.2.

The current source prompt, six included ledger/tool files, and twelve installed Codex profiles matched the existing `MAS1-v6.1-portable-20260918` snapshot byte for byte at intake. Older v1/v2/v4/v5 files and WIP candidates were not selected. This establishes the latest available local source, not a search for a globally authoritative upstream release.

Canonical prompt SHA-256:

```text
e8944e86049bb21196604a7a77470a7fe47a084cb8ddfed01964e2ef22a4b08f
```

## Preserved

- Canonical MAS1 prompt and optional Polishing Prompt 1 reference.
- Twelve original model-pinned Codex profiles.
- Ledger schema and synthetic fixture data.
- Production validation logic, original model checks, historical compatibility commitments, and invalidated-cutover catalogue.

## Public distribution changes

- Resolve tool module roots relative to `__file__`; fixture-runner defaults use the adjacent schema/fixture files. Historical catalogue paths/identities remain unchanged to avoid falsifying pinned evidence.
- Replace two analyzer-test rollout inputs with explicitly synthetic temporary manifests, preserving the original rejection assertions without publishing private rollout masters.
- Add portable workflow revision 1, chat starter, native Claude roles, portable Codex roles, project installer, public checks, documentation and CI.
- Correct a stale task-packet execution-channel example to avoid suggesting browser-courier support.
- Report private-evidence regression exclusions explicitly. Do not claim those tests passed publicly.

The original source digests are in `VERSION.json`. `SHA256SUMS` records public distribution bytes. Digests detect changes relative to these records; they do not authenticate the publisher, prove runtime model identity, or certify agent isolation.

## Excluded from publication

Private witness ledgers, client/project artifacts, migration payload files, source-machine rollout master files and incident documents, personal global configuration, sessions, credentials, unrelated prompts, and old WIP copies. Historical identifiers and path literals embedded in the original source code remain as compatibility metadata; they are not bundled evidence or instructions to access the author's machine.

The new repository starts with clean history. No source workspace Git history is imported.
